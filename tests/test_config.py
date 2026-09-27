import os
import tempfile
import pytest
from modules.config_loader import load_blueprint, TenantBlueprint


def create_temp_yaml(content: str) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8")
    tmp.write(content)
    tmp.close()
    return tmp.name


def test_valid_blueprint():
    yaml_content = """
tenant:
  name: "test-tenant"
networks:
  - name: "test-net"
    subnets:
      - name: "test-sub"
        cidr: "10.0.0.0/24"
        ip_version: 4
routers:
  - name: "test-router"
    external_gateway_network: "public"
    interfaces:
      - subnet_name: "test-sub"
security_groups:
  - name: "test-sg"
    rules:
      - direction: "ingress"
        protocol: "tcp"
        port_range_min: 80
        port_range_max: 80
        remote_ip_prefix: "0.0.0.0/0"
"""
    tmp_path = create_temp_yaml(yaml_content)
    try:
        bp = load_blueprint(tmp_path)
        assert isinstance(bp, TenantBlueprint)
        assert bp.tenant.name == "test-tenant"
        assert len(bp.networks) == 1
        assert bp.networks[0].subnets[0].cidr == "10.0.0.0/24"
        assert bp.security_groups[0].rules[0].port_range_min == 80
    finally:
        os.remove(tmp_path)


def test_invalid_cidr():
    yaml_content = """
tenant:
  name: "invalid-cidr-tenant"
networks:
  - name: "bad-net"
    subnets:
      - name: "bad-sub"
        cidr: "999.999.999.999/99"
"""
    tmp_path = create_temp_yaml(yaml_content)
    try:
        with pytest.raises(ValueError) as excinfo:
            load_blueprint(tmp_path)
        assert "Invalid CIDR format" in str(excinfo.value)
    finally:
        os.remove(tmp_path)


def test_invalid_port_range():
    yaml_content = """
tenant:
  name: "invalid-port-tenant"
security_groups:
  - name: "bad-sg"
    rules:
      - direction: "ingress"
        protocol: "tcp"
        port_range_min: 70000
        port_range_max: 80000
"""
    tmp_path = create_temp_yaml(yaml_content)
    try:
        with pytest.raises(ValueError) as excinfo:
            load_blueprint(tmp_path)
        assert "Port range must be between 0 and 65535" in str(excinfo.value)
    finally:
        os.remove(tmp_path)


def test_min_port_greater_than_max():
    yaml_content = """
tenant:
  name: "bad-min-max"
security_groups:
  - name: "bad-sg"
    rules:
      - direction: "ingress"
        protocol: "tcp"
        port_range_min: 500
        port_range_max: 100
"""
    tmp_path = create_temp_yaml(yaml_content)
    try:
        with pytest.raises(ValueError) as excinfo:
            load_blueprint(tmp_path)
        assert "cannot be greater than port_range_max" in str(excinfo.value)
    finally:
        os.remove(tmp_path)


def test_invalid_direction():
    yaml_content = """
tenant:
  name: "bad-dir"
security_groups:
  - name: "bad-sg"
    rules:
      - direction: "inbound_wrong"
        protocol: "tcp"
"""
    tmp_path = create_temp_yaml(yaml_content)
    try:
        with pytest.raises(ValueError) as excinfo:
            load_blueprint(tmp_path)
        assert "Direction must be 'ingress' or 'egress'" in str(excinfo.value)
    finally:
        os.remove(tmp_path)
