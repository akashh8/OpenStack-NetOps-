import logging
from typing import List, Dict, Any, Optional
from openstack.connection import Connection

logger = logging.getLogger("openstack_netops.auditor")

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
}


class SecurityAuditor:
    """
    Scans OpenStack Neutron security groups for compliance violations, risky rules,
    and offers automated remediation to enforce security baselines.
    """

    def __init__(self, conn: Connection):
        self.conn = conn

    def audit(self, remediate: bool = False) -> List[Dict[str, Any]]:
        """
        Queries active security groups and flags rules allowing sensitive ports from 0.0.0.0/0.
        If remediate is True, automatically purges non-compliant rules.
        """
        logger.info("Starting security compliance audit on active Neutron security groups...")
        violations = []

        try:
            sec_groups = list(self.conn.network.security_groups())
            logger.info(f"Auditing {len(sec_groups)} security groups...")

            for sg in sec_groups:
                sg_violations = self._audit_security_group(sg)
                violations.extend(sg_violations)

            logger.info(f"Audit completed. Found {len(violations)} compliance violations.")

            if remediate and violations:
                logger.warning("Remediation flag enabled. Purging high-risk compliance violations...")
                remediated_count = self._remediate_violations(violations)
                logger.info(f"Successfully remediated {remediated_count} security rules.")

            return violations

        except Exception as e:
            logger.error(f"Error executing security audit: {e}")
            raise

    def _audit_security_group(self, sg) -> List[Dict[str, Any]]:
        """
        Inspects rules inside a security group.
        """
        violations = []
        rules = list(self.conn.network.security_group_rules(security_group_id=sg.id))

        for rule in rules:
            # We are inspecting Ingress rules with open CIDR 0.0.0.0/0
            if rule.direction == "ingress" and rule.remote_ip_prefix in ["0.0.0.0/0", "::/0", None]:
                min_port = rule.port_range_min
                max_port = rule.port_range_max

                # Catch ALL ports (min_port is None or 0-65535 full range)
                is_all_ports = min_port is None or (min_port == 1 and max_port == 65535) or (min_port == 0 and max_port == 65535)

                flagged_services = []

                if is_all_ports:
                    flagged_services.append("ALL PORTS OPEN (0-65535)")
                else:
                    for port, service in SENSITIVE_PORTS.items():
                        if min_port is not None and max_port is not None:
                            if min_port <= port <= max_port:
                                flagged_services.append(f"{service} (Port {port})")

                if flagged_services:
                    violation_data = {
                        "security_group_id": sg.id,
                        "security_group_name": sg.name,
                        "rule_id": rule.id,
                        "protocol": rule.protocol,
                        "port_range": f"{min_port}-{max_port}" if min_port is not None else "ALL",
                        "remote_ip_prefix": rule.remote_ip_prefix or "0.0.0.0/0",
                        "flagged_services": flagged_services,
                        "severity": "CRITICAL" if is_all_ports or any(p in flagged_services for p in ["SSH (Port 22)", "RDP (Port 3389)"]) else "HIGH",
                        "description": f"Ingress rule exposes {', '.join(flagged_services)} to public internet ({rule.remote_ip_prefix})",
                    }
                    logger.warning(
                        f"VIOLATION DETECTED in SG '{sg.name}' (Rule ID: {rule.id}): {violation_data['description']}"
                    )
                    violations.append(violation_data)

        return violations

    def _remediate_violations(self, violations: List[Dict[str, Any]]) -> int:
        """
        Remediates violations by deleting non-compliant high-risk rules.
        """
        remediated = 0
        for v in violations:
            rule_id = v["rule_id"]
            sg_name = v["security_group_name"]
            logger.info(f"Remediating violation: Deleting rule {rule_id} from Security Group '{sg_name}'")
            try:
                self.conn.network.delete_security_group_rule(rule_id)
                remediated += 1
                logger.info(f"Deleted rule {rule_id} successfully.")
            except Exception as e:
                logger.error(f"Failed to delete non-compliant rule {rule_id}: {e}")
        return remediated
