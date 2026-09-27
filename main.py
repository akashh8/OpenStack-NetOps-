import os
import sys
import argparse
import logging
from tabulate import tabulate

from modules.config_loader import load_blueprint
from modules.client import OpenStackClient
from modules.provisioner import InfrastructureProvisioner
from modules.auditor import SecurityAuditor
from modules.health import HealthChecker


def setup_logging():
    """Configures dual logging to console and logs/automation.log file."""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "automation.log")

    log_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


def handle_provision(args):
    """Subcommand handler for infrastructure provisioning."""
    print("\n=== OpenStack NetOps: Provisioning Infrastructure ===")
    blueprint = load_blueprint(args.config)

    client = OpenStackClient()
    conn = client.get_connection()

    provisioner = InfrastructureProvisioner(conn)
    summary = provisioner.provision(blueprint)

    print("\n--- Provisioning Summary ---")
    print(f"Tenant: {summary['tenant']}")
    print(f"Networks Created/Verified ({len(summary['networks'])}): {', '.join(summary['networks'])}")
    print(f"Subnets Created/Verified ({len(summary['subnets'])}): {', '.join(summary['subnets'])}")
    print(f"Routers Created/Verified ({len(summary['routers'])}): {', '.join(summary['routers'])}")
    print(f"Security Groups Created/Verified ({len(summary['security_groups'])}): {', '.join([sg['name'] for sg in summary['security_groups']])}")
    if summary["floating_ips"]:
        print(f"Floating IPs Allocated: {', '.join(summary['floating_ips'])}")
    print("====================================================\n")


def handle_audit(args):
    """Subcommand handler for security compliance auditing."""
    print("\n=== OpenStack NetOps: Security Compliance Audit ===")
    client = OpenStackClient()
    conn = client.get_connection()

    auditor = SecurityAuditor(conn)
    violations = auditor.audit(remediate=args.remediate)

    if not violations:
        print("\n[SUCCESS] No security compliance violations detected.")
    else:
        table_data = []
        for v in violations:
            table_data.append([
                v["security_group_name"],
                v["rule_id"],
                v["protocol"],
                v["port_range"],
                v["remote_ip_prefix"],
                v["severity"],
                ", ".join(v["flagged_services"]),
            ])
        headers = ["SecGroup", "Rule ID", "Proto", "Ports", "Remote CIDR", "Severity", "Flagged Services"]
        print("\n" + tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nTotal Violations Found: {len(violations)}")
        if args.remediate:
            print("[INFO] Automatic remediation executed on non-compliant rules.")

    print("===================================================\n")


def handle_health(args):
    """Subcommand handler for overlay health diagnostic checks."""
    print("\n=== OpenStack NetOps: Overlay Health Diagnostics ===")
    client = OpenStackClient()
    conn = client.get_connection()

    checker = HealthChecker(conn)
    report = checker.run_health_checks(output_path=args.output)

    print(f"\nOverall Health Status: [{report['overall_status']}]")
    print(f"Total Routers: {report['summary']['total_routers']} (Active: {report['summary']['active_routers']})")
    print(f"Total Subnets: {report['summary']['total_subnets']} (Healthy: {report['summary']['healthy_subnets']})")

    if report["router_checks"]:
        r_table = []
        for r in report["router_checks"]:
            r_table.append([
                r["router_name"],
                r["status"],
                r["external_gateway_attached"],
                r["connected_interfaces_count"],
                f"{r['api_response_latency_ms']} ms",
                "PASS" if r["healthy"] else "FAIL",
            ])
        print("\n--- Router Health ---")
        print(tabulate(r_table, headers=["Router Name", "Status", "Ext Gateway", "Interfaces", "API Latency", "Health"], tablefmt="simple"))

    print(f"\nReport written to: {args.output}")
    print("====================================================\n")


def main():
    setup_logging()

    parser = argparse.ArgumentParser(
        description="openstack-netops: Multi-tenant OpenStack Neutron Infrastructure & Security CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available NetOps Subcommands")

    # Subcommand: provision
    prov_parser = subparsers.add_parser("provision", help="Declaratively provision network infrastructure")
    prov_parser.add_argument(
        "--config",
        default="config/tenant_blueprint.yaml",
        help="Path to tenant YAML blueprint file (default: config/tenant_blueprint.yaml)",
    )
    prov_parser.set_defaults(func=handle_provision)

    # Subcommand: audit
    audit_parser = subparsers.add_parser("audit", help="Audit active Neutron security groups for compliance")
    audit_parser.add_argument(
        "--remediate",
        action="store_true",
        help="Automatically purge non-compliant high-risk security group rules",
    )
    audit_parser.set_defaults(func=handle_audit)

    # Subcommand: health-check
    health_parser = subparsers.add_parser("health-check", help="Check operational status of overlay routers & subnets")
    health_parser.add_argument(
        "--output",
        default="reports/health_report.json",
        help="Path to output JSON report (default: reports/health_report.json)",
    )
    health_parser.set_defaults(func=handle_health)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        args.func(args)
    except Exception as e:
        logging.error(f"Execution failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
