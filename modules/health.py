import os
import json
import time
import logging
from typing import Dict, Any, List
from openstack.connection import Connection

logger = logging.getLogger("openstack_netops.health")


class HealthChecker:
    """
    Programmatically verifies Neutron overlay network health, router operational status,
    subnet gateway attachments, and generates structured JSON telemetry reports.
    """

    def __init__(self, conn: Connection):
        self.conn = conn

    def run_health_checks(self, output_path: str = "reports/health_report.json") -> Dict[str, Any]:
        """
        Runs comprehensive overlay health diagnostic checks and outputs report to output_path.
        """
        logger.info("Initiating OpenStack Neutron overlay network health checks...")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        report = {
            "timestamp": timestamp,
            "overall_status": "PASS",
            "summary": {"total_routers": 0, "active_routers": 0, "total_subnets": 0, "healthy_subnets": 0},
            "router_checks": [],
            "subnet_checks": [],
            "simulated_telemetry": [],
        }

        try:
            # 1. Router Operational Status Checks
            routers = list(self.conn.network.routers())
            report["summary"]["total_routers"] = len(routers)

            for r in routers:
                start_time = time.time()
                r_status = getattr(r, "status", "UNKNOWN")
                has_gateway = bool(r.external_gateway_info)
                ports = list(self.conn.network.ports(device_id=r.id))
                latency_ms = round((time.time() - start_time) * 1000, 2)

                is_healthy = r_status.upper() == "ACTIVE" and len(ports) > 0
                if is_healthy:
                    report["summary"]["active_routers"] += 1
                else:
                    report["overall_status"] = "WARN"

                router_info = {
                    "router_id": r.id,
                    "router_name": r.name,
                    "status": r_status,
                    "admin_state_up": r.admin_state_up,
                    "external_gateway_attached": has_gateway,
                    "connected_interfaces_count": len(ports),
                    "api_response_latency_ms": latency_ms,
                    "healthy": is_healthy,
                }
                report["router_checks"].append(router_info)
                logger.info(f"Router '{r.name}' status: {r_status}, Gateway: {has_gateway}, Latency: {latency_ms}ms")

            # 2. Subnet Health & Gateway Checks
            subnets = list(self.conn.network.subnets())
            report["summary"]["total_subnets"] = len(subnets)

            for sub in subnets:
                has_gateway_ip = bool(sub.gateway_ip)
                dhcp_enabled = sub.enable_dhcp
                is_sub_healthy = has_gateway_ip

                if is_sub_healthy:
                    report["summary"]["healthy_subnets"] += 1

                subnet_info = {
                    "subnet_id": sub.id,
                    "subnet_name": sub.name,
                    "cidr": sub.cidr,
                    "gateway_ip": sub.gateway_ip,
                    "dhcp_enabled": dhcp_enabled,
                    "healthy": is_sub_healthy,
                }
                report["subnet_checks"].append(subnet_info)

            # 3. Simulated Port Connectivity & Overlay Latency Telemetry
            logger.info("Executing simulated overlay network port connectivity check...")
            telemetry_data = self._simulate_overlay_telemetry(routers)
            report["simulated_telemetry"] = telemetry_data

            # Save JSON report
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            logger.info(f"Health report successfully saved to {output_path}")
            return report

        except Exception as e:
            logger.error(f"Health check execution failed: {e}")
            report["overall_status"] = "FAIL"
            report["error"] = str(e)
            return report

    def _simulate_overlay_telemetry(self, routers: List[Any]) -> List[Dict[str, Any]]:
        """
        Simulates overlay dataplane check across active virtual routers.
        """
        telemetry = []
        for r in routers:
            sim_result = {
                "router_name": r.name,
                "overlay_tunnel_status": "UP" if r.admin_state_up else "DOWN",
                "simulated_packet_loss_pct": 0.0 if r.admin_state_up else 100.0,
                "simulated_avg_rtt_ms": 1.45 if r.admin_state_up else 0.0,
                "mtu_compliance": "PASS",
            }
            telemetry.append(sim_result)
        return telemetry
