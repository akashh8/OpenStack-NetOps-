import logging
from typing import Dict, Any, List, Optional
from openstack.connection import Connection
from openstack.exceptions import SDKException
from modules.config_loader import TenantBlueprint, NetworkSpec, RouterSpec, SecurityGroupSpec, SecurityRuleSpec

logger = logging.getLogger("openstack_netops.provisioner")


class InfrastructureProvisioner:
    """
    Handles declarative, idempotent provisioning of OpenStack Neutron networking resources.
    """

    def __init__(self, conn: Connection):
        self.conn = conn

    def provision(self, blueprint: TenantBlueprint) -> Dict[str, Any]:
        """
        Executes provisioning based on the provided blueprint.
        Returns a summary report of created/existing resources.
        """
        logger.info(f"Starting provisioning for tenant: {blueprint.tenant.name}")
        summary = {
            "tenant": blueprint.tenant.name,
            "networks": [],
            "subnets": [],
            "routers": [],
            "security_groups": [],
            "floating_ips": [],
        }

        try:
            # 1. Security Groups
            for sg_spec in blueprint.security_groups:
                sg_info = self.provision_security_group(sg_spec)
                summary["security_groups"].append(sg_info)

            # 2. Networks & Subnets
            subnet_name_map = {}  # subnet_name -> subnet_obj
            for net_spec in blueprint.networks:
                net_info = self.provision_network(net_spec)
                summary["networks"].append(net_info["name"])
                for sub_info in net_info["subnets"]:
                    summary["subnets"].append(sub_info["name"])
                    subnet_name_map[sub_info["name"]] = sub_info["object"]

            # 3. Routers & Interfaces
            for router_spec in blueprint.routers:
                router_info = self.provision_router(router_spec, subnet_name_map)
                summary["routers"].append(router_info["name"])

            # 4. Floating IPs
            for fip_spec in blueprint.floating_ips:
                fip_info = self.provision_floating_ip(fip_spec.network_name, fip_spec.description)
                summary["floating_ips"].append(fip_info["floating_ip_address"])

            logger.info(f"Provisioning completed successfully for tenant '{blueprint.tenant.name}'")
            return summary

        except Exception as e:
            logger.error(f"Error during tenant provisioning: {e}")
            raise

    def provision_security_group(self, sg_spec: SecurityGroupSpec) -> Dict[str, Any]:
        """
        Idempotently creates a security group and applies rules.
        """
        logger.info(f"Processing Security Group: {sg_spec.name}")
        sg = self.conn.network.find_security_group(sg_spec.name)

        if sg is None:
            logger.info(f"Creating Security Group: {sg_spec.name}")
            sg = self.conn.network.create_security_group(
                name=sg_spec.name,
                description=sg_spec.description or f"SecGroup for {sg_spec.name}",
            )
            logger.info(f"Created Security Group ID: {sg.id}")
        else:
            logger.info(f"Security Group '{sg_spec.name}' already exists (ID: {sg.id})")

        # Fetch current rules for this security group
        existing_rules = list(self.conn.network.security_group_rules(security_group_id=sg.id))

        # Add rules from spec idempotently
        for rule_spec in sg_spec.rules:
            self._add_rule_if_missing(sg.id, rule_spec, existing_rules)

        return {"name": sg_spec.name, "id": sg.id}

    def _add_rule_if_missing(self, sg_id: str, rule_spec: SecurityRuleSpec, existing_rules: List[Any]):
        """
        Checks if a rule already exists before creating it.
        """
        for r in existing_rules:
            if (
                r.direction == rule_spec.direction
                and r.protocol == rule_spec.protocol
                and r.port_range_min == rule_spec.port_range_min
                and r.port_range_max == rule_spec.port_range_max
                and r.remote_ip_prefix == rule_spec.remote_ip_prefix
            ):
                logger.debug(f"Rule {rule_spec.direction} {rule_spec.protocol} {rule_spec.port_range_min}-{rule_spec.port_range_max} already exists on SG {sg_id}")
                return

        logger.info(
            f"Creating security rule on SG {sg_id}: {rule_spec.direction} {rule_spec.protocol} "
            f"ports [{rule_spec.port_range_min}-{rule_spec.port_range_max}] CIDR {rule_spec.remote_ip_prefix}"
        )
        rule_params = {
            "security_group_id": sg_id,
            "direction": rule_spec.direction,
            "protocol": rule_spec.protocol,
            "port_range_min": rule_spec.port_range_min,
            "port_range_max": rule_spec.port_range_max,
            "remote_ip_prefix": rule_spec.remote_ip_prefix,
            "description": rule_spec.description,
        }
        # Filter out None values for SDK compatibility
        rule_params = {k: v for k, v in rule_params.items() if v is not None}
        self.conn.network.create_security_group_rule(**rule_params)

    def provision_network(self, net_spec: NetworkSpec) -> Dict[str, Any]:
        """
        Idempotently provisions a network and attached subnets.
        """
        logger.info(f"Processing Network: {net_spec.name}")
        network = self.conn.network.find_network(net_spec.name)

        if network is None:
            logger.info(f"Creating Network: {net_spec.name}")
            network = self.conn.network.create_network(
                name=net_spec.name,
                admin_state_up=net_spec.admin_state_up,
                is_shared=net_spec.shared,
            )
            logger.info(f"Created Network ID: {network.id}")
        else:
            logger.info(f"Network '{net_spec.name}' already exists (ID: {network.id})")

        subnets_info = []
        for sub_spec in net_spec.subnets:
            subnet = self.conn.network.find_subnet(sub_spec.name)
            if subnet is None:
                logger.info(f"Creating Subnet '{sub_spec.name}' (CIDR: {sub_spec.cidr}) on Network {network.id}")
                subnet_args = {
                    "name": sub_spec.name,
                    "network_id": network.id,
                    "cidr": sub_spec.cidr,
                    "ip_version": sub_spec.ip_version,
                    "enable_dhcp": sub_spec.enable_dhcp,
                    "dns_nameservers": sub_spec.dns_nameservers,
                }
                if sub_spec.gateway_ip:
                    subnet_args["gateway_ip"] = sub_spec.gateway_ip
                subnet = self.conn.network.create_subnet(**subnet_args)
                logger.info(f"Created Subnet ID: {subnet.id}")
            else:
                logger.info(f"Subnet '{sub_spec.name}' already exists (ID: {subnet.id})")

            subnets_info.append({"name": sub_spec.name, "id": subnet.id, "object": subnet})

        return {"name": net_spec.name, "id": network.id, "subnets": subnets_info}

    def provision_router(self, router_spec: RouterSpec, subnet_map: Dict[str, Any]) -> Dict[str, Any]:
        """
        Idempotently creates a router, attaches external gateway, and adds internal subnet interfaces.
        """
        logger.info(f"Processing Router: {router_spec.name}")
        router = self.conn.network.find_router(router_spec.name)

        if router is None:
            logger.info(f"Creating Router: {router_spec.name}")
            router_args = {"name": router_spec.name, "admin_state_up": router_spec.admin_state_up}
            router = self.conn.network.create_router(**router_args)
            logger.info(f"Created Router ID: {router.id}")
        else:
            logger.info(f"Router '{router_spec.name}' already exists (ID: {router.id})")

        # Set external gateway network if specified
        if router_spec.external_gateway_network:
            ext_net = self.conn.network.find_network(router_spec.external_gateway_network)
            if ext_net:
                ext_gateway_info = {"network_id": ext_net.id}
                current_ext_net_id = None
                if isinstance(router.external_gateway_info, dict):
                    current_ext_net_id = router.external_gateway_info.get("network_id")
                elif router.external_gateway_info:
                    current_ext_net_id = getattr(router.external_gateway_info, "network_id", None)

                if current_ext_net_id != ext_net.id:
                    logger.info(f"Attaching external gateway network '{ext_net.name}' to router '{router.name}'")
                    self.conn.network.update_router(router.id, external_gateway_info=ext_gateway_info)
            else:
                logger.warning(f"External gateway network '{router_spec.external_gateway_network}' not found")

        # Attach internal subnets idempotently
        for iface in router_spec.interfaces:
            subnet = subnet_map.get(iface.subnet_name) or self.conn.network.find_subnet(iface.subnet_name)
            if subnet:
                self._attach_subnet_to_router(router, subnet)
            else:
                logger.error(f"Subnet '{iface.subnet_name}' not found; cannot attach to router '{router_spec.name}'")

        return {"name": router_spec.name, "id": router.id}

    def _attach_subnet_to_router(self, router, subnet):
        """
        Attaches a subnet interface to a router if not already attached.
        """
        # Query ports associated with this router
        ports = list(self.conn.network.ports(device_id=router.id))
        attached_subnet_ids = set()
        for p in ports:
            for ip_info in p.fixed_ips:
                attached_subnet_ids.add(ip_info.get("subnet_id"))

        if subnet.id in attached_subnet_ids:
            logger.info(f"Subnet '{subnet.name}' ({subnet.id}) is already attached to router '{router.name}'")
        else:
            logger.info(f"Attaching Subnet '{subnet.name}' ({subnet.id}) interface to router '{router.name}'")
            try:
                self.conn.network.add_interface_to_router(router.id, subnet_id=subnet.id)
                logger.info(f"Successfully attached subnet '{subnet.name}' to router '{router.name}'")
            except SDKException as e:
                logger.warning(f"Failed to attach subnet '{subnet.name}' to router: {e}")

    def provision_floating_ip(self, ext_net_name: str, description: Optional[str] = None) -> Dict[str, Any]:
        """
        Allocates a floating IP from the external network.
        """
        logger.info(f"Allocating floating IP from network: {ext_net_name}")
        ext_net = self.conn.network.find_network(ext_net_name)
        if not ext_net:
            raise ValueError(f"External network '{ext_net_name}' not found for floating IP allocation")

        fip = self.conn.network.create_ip(
            floating_network_id=ext_net.id,
            description=description or "Allocated by openstack-netops",
        )
        logger.info(f"Allocated Floating IP: {fip.floating_ip_address} (ID: {fip.id})")
        return {"id": fip.id, "floating_ip_address": fip.floating_ip_address}
