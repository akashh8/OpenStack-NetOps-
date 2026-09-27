from unittest.mock import MagicMock
from modules.config_loader import (
    TenantBlueprint,
    TenantSpec,
    NetworkSpec,
    SubnetSpec,
    RouterSpec,
    RouterInterfaceSpec,
    SecurityGroupSpec,
    SecurityRuleSpec,
)
from modules.provisioner import InfrastructureProvisioner
from modules.auditor import SecurityAuditor
from modules.health import HealthChecker


def test_idempotent_provisioner_creates_resources():
    mock_conn = MagicMock()

    # Configure network return values (None means not found, triggering create)
    mock_conn.network.find_security_group.return_value = None
    mock_conn.network.find_network.return_value = None
    mock_conn.network.find_subnet.return_value = None
    mock_conn.network.find_router.return_value = None

    mock_sg = MagicMock()
    mock_sg.id = "sg-123"
    mock_sg.name = "app-sg"
    mock_conn.network.create_security_group.return_value = mock_sg
    mock_conn.network.security_group_rules.return_value = []

    mock_net = MagicMock()
    mock_net.id = "net-123"
    mock_net.name = "app-net"
    mock_conn.network.create_network.return_value = mock_net

    mock_sub = MagicMock()
    mock_sub.id = "sub-123"
    mock_sub.name = "app-subnet"
    mock_conn.network.create_subnet.return_value = mock_sub

    mock_router = MagicMock()
    mock_router.id = "rtr-123"
    mock_router.name = "app-router"
    mock_router.external_gateway_info = None
    mock_conn.network.create_router.return_value = mock_router
    mock_conn.network.ports.return_value = []

    blueprint = TenantBlueprint(
        tenant=TenantSpec(name="test-tenant"),
        security_groups=[
            SecurityGroupSpec(
                name="app-sg",
                rules=[
                    SecurityRuleSpec(
                        direction="ingress",
                        protocol="tcp",
                        port_range_min=80,
                        port_range_max=80,
                        remote_ip_prefix="0.0.0.0/0",
                    )
                ],
            )
        ],
        networks=[
            NetworkSpec(
                name="app-net",
                subnets=[SubnetSpec(name="app-subnet", cidr="10.0.1.0/24")],
            )
        ],
        routers=[
            RouterSpec(
                name="app-router",
                external_gateway_network="public",
                interfaces=[RouterInterfaceSpec(subnet_name="app-subnet")],
            )
        ],
    )

    provisioner = InfrastructureProvisioner(mock_conn)
    summary = provisioner.provision(blueprint)

    assert summary["tenant"] == "test-tenant"
    assert "app-net" in summary["networks"]
    assert "app-subnet" in summary["subnets"]
    assert "app-router" in summary["routers"]

    mock_conn.network.create_security_group.assert_called_once()
    mock_conn.network.create_network.assert_called_once()
    mock_conn.network.create_subnet.assert_called_once()
    mock_conn.network.create_router.assert_called_once()


def test_auditor_detects_violations():
    mock_conn = MagicMock()

    mock_sg = MagicMock()
    mock_sg.id = "sg-risky"
    mock_sg.name = "default-risky-sg"
    mock_conn.network.security_groups.return_value = [mock_sg]

    mock_rule = MagicMock()
    mock_rule.id = "rule-ssh"
    mock_rule.direction = "ingress"
    mock_rule.protocol = "tcp"
    mock_rule.port_range_min = 22
    mock_rule.port_range_max = 22
    mock_rule.remote_ip_prefix = "0.0.0.0/0"
    mock_conn.network.security_group_rules.return_value = [mock_rule]

    auditor = SecurityAuditor(mock_conn)
    violations = auditor.audit(remediate=False)

    assert len(violations) == 1
    assert violations[0]["security_group_name"] == "default-risky-sg"
    assert violations[0]["rule_id"] == "rule-ssh"
    assert violations[0]["severity"] == "CRITICAL"


def test_auditor_remediates_violations():
    mock_conn = MagicMock()

    mock_sg = MagicMock()
    mock_sg.id = "sg-risky"
    mock_sg.name = "default-risky-sg"
    mock_conn.network.security_groups.return_value = [mock_sg]

    mock_rule = MagicMock()
    mock_rule.id = "rule-rdp"
    mock_rule.direction = "ingress"
    mock_rule.protocol = "tcp"
    mock_rule.port_range_min = 3389
    mock_rule.port_range_max = 3389
    mock_rule.remote_ip_prefix = "0.0.0.0/0"
    mock_conn.network.security_group_rules.return_value = [mock_rule]

    auditor = SecurityAuditor(mock_conn)
    violations = auditor.audit(remediate=True)

    assert len(violations) == 1
    mock_conn.network.delete_security_group_rule.assert_called_once_with("rule-rdp")


def test_health_checker_runs(tmp_path):
    mock_conn = MagicMock()

    mock_router = MagicMock()
    mock_router.id = "rtr-1"
    mock_router.name = "edge-rtr"
    mock_router.status = "ACTIVE"
    mock_router.admin_state_up = True
    mock_router.external_gateway_info = {"network_id": "public-id"}
    mock_conn.network.routers.return_value = [mock_router]

    mock_subnet = MagicMock()
    mock_subnet.id = "sub-1"
    mock_subnet.name = "sub-app"
    mock_subnet.cidr = "10.0.0.0/24"
    mock_subnet.gateway_ip = "10.0.0.1"
    mock_subnet.enable_dhcp = True
    mock_conn.network.subnets.return_value = [mock_subnet]
    mock_conn.network.ports.return_value = [MagicMock()]

    checker = HealthChecker(mock_conn)
    report_file = tmp_path / "health_report.json"
    report = checker.run_health_checks(output_path=str(report_file))

    assert report["overall_status"] == "PASS"
    assert report["summary"]["total_routers"] == 1
    assert report["summary"]["active_routers"] == 1
    assert report["summary"]["total_subnets"] == 1
    assert report["summary"]["healthy_subnets"] == 1
