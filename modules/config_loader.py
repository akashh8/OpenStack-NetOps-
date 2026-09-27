import ipaddress
import yaml
import logging
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger("openstack_netops.config_loader")


class SecurityRuleSpec(BaseModel):
    direction: str = Field(..., description="ingress or egress")
    protocol: str = Field(..., description="tcp, udp, icmp, or null")
    port_range_min: Optional[int] = Field(None, description="Minimum port (0-65535)")
    port_range_max: Optional[int] = Field(None, description="Maximum port (0-65535)")
    remote_ip_prefix: Optional[str] = Field("0.0.0.0/0", description="CIDR format remote IP prefix")
    description: Optional[str] = Field(None, description="Rule description")

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, v: str) -> str:
        if v.lower() not in ["ingress", "egress"]:
            raise ValueError(f"Direction must be 'ingress' or 'egress', got '{v}'")
        return v.lower()

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.lower() not in ["tcp", "udp", "icmp", "any", "all"]:
            raise ValueError(f"Protocol must be one of ['tcp', 'udp', 'icmp', 'any', 'all'], got '{v}'")
        return v.lower() if v else None

    @field_validator("port_range_min", "port_range_max")
    @classmethod
    def validate_port_range(cls, v: Optional[int]) -> Optional[int]:
        if v is not None:
            if not (0 <= v <= 65535):
                raise ValueError(f"Port range must be between 0 and 65535, got {v}")
        return v

    @field_validator("remote_ip_prefix")
    @classmethod
    def validate_remote_prefix(cls, v: Optional[str]) -> Optional[str]:
        if v:
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid remote IP prefix CIDR notation '{v}': {e}")
        return v

    @model_validator(mode="after")
    def validate_min_max_ports(self):
        if self.port_range_min is not None and self.port_range_max is not None:
            if self.port_range_min > self.port_range_max:
                raise ValueError(
                    f"port_range_min ({self.port_range_min}) cannot be greater than port_range_max ({self.port_range_max})"
                )
        return self


class SecurityGroupSpec(BaseModel):
    name: str = Field(..., description="Security group name")
    description: Optional[str] = Field(None, description="Security group description")
    rules: List[SecurityRuleSpec] = Field(default_factory=list)


class SubnetSpec(BaseModel):
    name: str = Field(..., description="Subnet name")
    cidr: str = Field(..., description="IPv4 or IPv6 CIDR prefix")
    ip_version: int = Field(4, description="IP version: 4 or 6")
    enable_dhcp: bool = Field(True, description="Enable DHCP on subnet")
    dns_nameservers: List[str] = Field(default_factory=list, description="DNS server IPs")
    gateway_ip: Optional[str] = Field(None, description="Custom gateway IP")

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR format '{v}': {e}")
        return v

    @field_validator("ip_version")
    @classmethod
    def validate_ip_version(cls, v: int) -> int:
        if v not in [4, 6]:
            raise ValueError(f"ip_version must be 4 or 6, got {v}")
        return v


class NetworkSpec(BaseModel):
    name: str = Field(..., description="Network name")
    admin_state_up: bool = Field(True, description="Admin state up")
    shared: bool = Field(False, description="Is shared network")
    subnets: List[SubnetSpec] = Field(default_factory=list)


class RouterInterfaceSpec(BaseModel):
    subnet_name: str = Field(..., description="Name of internal subnet to attach")


class RouterSpec(BaseModel):
    name: str = Field(..., description="Router name")
    admin_state_up: bool = Field(True, description="Admin state up")
    external_gateway_network: Optional[str] = Field(None, description="Name of external/provider network")
    interfaces: List[RouterInterfaceSpec] = Field(default_factory=list)


class FloatingIPSpec(BaseModel):
    network_name: str = Field(..., description="External network for floating IP pool")
    description: Optional[str] = Field(None, description="Description")


class TenantSpec(BaseModel):
    name: str = Field(..., description="Tenant / Project name")
    description: Optional[str] = Field(None, description="Tenant description")


class TenantBlueprint(BaseModel):
    tenant: TenantSpec
    networks: List[NetworkSpec] = Field(default_factory=list)
    routers: List[RouterSpec] = Field(default_factory=list)
    security_groups: List[SecurityGroupSpec] = Field(default_factory=list)
    floating_ips: List[FloatingIPSpec] = Field(default_factory=list)


def load_blueprint(config_path: str) -> TenantBlueprint:
    """
    Parses and validates a tenant YAML blueprint file.
    Returns a validated TenantBlueprint object or raises ValueError with human-readable error details.
    """
    logger.info(f"Loading configuration blueprint from: {config_path}")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to read file '{config_path}': {e}")
        raise ValueError(f"Could not read YAML configuration file: {e}")

    if not raw_data:
        raise ValueError(f"YAML configuration file '{config_path}' is empty")

    try:
        blueprint = TenantBlueprint.model_validate(raw_data)
        logger.info(f"Successfully validated blueprint for tenant '{blueprint.tenant.name}'")
        return blueprint
    except Exception as e:
        logger.error(f"Blueprint validation failed for '{config_path}':\n{e}")
        raise ValueError(f"Validation Error in {config_path}:\n{e}")
