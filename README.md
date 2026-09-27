# openstack-netops

`openstack-netops` is a production-grade, modular Python CLI tool designed to automate multi-tenant infrastructure provisioning, security compliance auditing, and health monitoring for **OpenStack Neutron**.

Built on clean architecture principles, `openstack-netops` provides Infrastructure-as-Code (IaC) capabilities using declarative YAML blueprint specifications and the official `openstacksdk`.

---

## Key Features

- **Declarative Infrastructure Provisioning**: Idempotently creates isolated tenant networks, IPv4/IPv6 subnets, virtual routers, external gateway attachments, floating IPs, and security groups.
- **Security Compliance Auditing**: Automatically audits active Neutron security groups to flag high-risk ingress rules (e.g. `0.0.0.0/0` access to SSH `22`, RDP `3389`, MySQL `3306`, PostgreSQL `5432`).
- **Automated Policy Remediation**: Offers an automated `--remediate` option to automatically purge or patch non-compliant security rules.
- **Overlay Telemetry & Health Monitoring**: Programmatically verifies router operational status (`ACTIVE`), gateway connections, subnet configurations, and simulated overlay network latency.
- **Structured Telemetry Reporting**: Outputs JSON reports (`reports/health_report.json`) and timestamped execution logs (`logs/automation.log`).

---

## Directory Layout

```text
openstack-netops/
├── config/
│   └── tenant_blueprint.yaml    # Declarative multi-tenant YAML blueprint
├── modules/
│   ├── __init__.py
│   ├── client.py               # OpenStack SDK connection factory
│   ├── config_loader.py        # Pydantic schema validation & YAML parser
│   ├── parser.py               # Alias loader module
│   ├── provisioner.py          # Idempotent infrastructure provisioner
│   ├── auditor.py              # Security group compliance auditor & policy enforcer
│   └── health.py               # Overlay health & latency telemetry checker
├── tests/
│   ├── __init__.py
│   ├── test_config.py          # Unit tests for schema validation
│   └── test_provisioner.py     # Unit tests with mocked OpenStack SDK
├── main.py                     # CLI entrypoint with subcommands
├── requirements.txt            # Project dependencies
└── README.md                   # Complete documentation
```

---

## Prerequisites & Installation

### 1. Requirements
- Python 3.10+
- OpenStack environment (MicroStack, DevStack, or Enterprise OpenStack Cloud API endpoint)

### 2. Installation
Clone the repository and install the dependencies:
```bash
cd openstack-netops
pip install -r requirements.txt
```

---

## Environment Credentials Configuration

`openstack-netops` uses standard OpenStack `OS_*` environment variables for authentication. Source your `openrc` file or export the following variables:

```bash
export OS_AUTH_URL="http://<openstack-controller-ip>:5000/v3"
export OS_PROJECT_NAME="admin"
export OS_USERNAME="admin"
export OS_PASSWORD="your-secret-password"
export OS_USER_DOMAIN_NAME="Default"
export OS_PROJECT_DOMAIN_NAME="Default"
export OS_REGION_NAME="RegionOne"
```

---

## Declarative Tenant Blueprint Schema

Intent specifications are declared in YAML under `config/tenant_blueprint.yaml`:

```yaml
tenant:
  name: "finance-production"
  description: "Finance Department Core Infrastructure"

networks:
  - name: "finance-app-net"
    admin_state_up: true
    shared: false
    subnets:
      - name: "finance-app-subnet"
        cidr: "192.168.10.0/24"
        ip_version: 4
        enable_dhcp: true
        dns_nameservers:
          - "8.8.8.8"
        gateway_ip: "192.168.10.1"

routers:
  - name: "finance-edge-router"
    admin_state_up: true
    external_gateway_network: "public"
    interfaces:
      - subnet_name: "finance-app-subnet"

security_groups:
  - name: "app-secgroup"
    description: "Security Group for Application Servers"
    rules:
      - direction: "ingress"
        protocol: "tcp"
        port_range_min: 80
        port_range_max: 80
        remote_ip_prefix: "0.0.0.0/0"
        description: "Allow HTTP public traffic"
      - direction: "ingress"
        protocol: "tcp"
        port_range_min: 22
        port_range_max: 22
        remote_ip_prefix: "10.0.0.0/8"
        description: "Restrict SSH to internal management network"
```

---

## CLI Command Usage

### 1. Provision Network Infrastructure
Declaratively provision networks, subnets, routers, interfaces, and security groups:
```bash
python main.py provision --config config/tenant_blueprint.yaml
```

### 2. Audit Security Group Compliance
Scan active security groups for risky public ingress rules:
```bash
python main.py audit
```

To automatically delete non-compliant high-risk rules:
```bash
python main.py audit --remediate
```

### 3. Run Overlay Health Diagnostics
Perform health checks on virtual routers and subnets, generating a JSON telemetry report:
```bash
python main.py health-check --output reports/health_report.json
```

---

## Running Unit Tests

Run `pytest` to execute unit tests for schema validation and mock SDK interactions:

```bash
pytest -v tests/
```
