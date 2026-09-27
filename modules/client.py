import os
import logging
from typing import Optional
import openstack
from openstack.connection import Connection
from openstack.exceptions import SDKException

logger = logging.getLogger("openstack_netops.client")


class OpenStackClient:
    """
    Centralized connection factory for OpenStack SDK.
    Reads authentication details from OS_* environment variables or explicit parameters.
    """

    def __init__(
        self,
        auth_url: Optional[str] = None,
        project_name: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        user_domain_name: Optional[str] = None,
        project_domain_name: Optional[str] = None,
        region_name: Optional[str] = None,
    ):
        self.auth_url = auth_url or os.getenv("OS_AUTH_URL")
        self.project_name = project_name or os.getenv("OS_PROJECT_NAME")
        self.username = username or os.getenv("OS_USERNAME")
        self.password = password or os.getenv("OS_PASSWORD")
        self.user_domain_name = user_domain_name or os.getenv("OS_USER_DOMAIN_NAME", "Default")
        self.project_domain_name = project_domain_name or os.getenv("OS_PROJECT_DOMAIN_NAME", "Default")
        self.region_name = region_name or os.getenv("OS_REGION_NAME")
        self._conn: Optional[Connection] = None

    def get_connection(self) -> Connection:
        """
        Initializes and returns an openstacksdk Connection object.
        Caches the active connection.
        """
        if self._conn is not None:
            return self._conn

        logger.info("Initializing OpenStack SDK connection...")

        # Validate required environment parameters for authenticating
        missing_vars = []
        if not self.auth_url:
            missing_vars.append("OS_AUTH_URL")
        if not self.project_name:
            missing_vars.append("OS_PROJECT_NAME")
        if not self.username:
            missing_vars.append("OS_USERNAME")
        if not self.password:
            missing_vars.append("OS_PASSWORD")

        if missing_vars:
            err_msg = f"Missing required OpenStack environment variables: {', '.join(missing_vars)}"
            logger.error(err_msg)
            raise ConnectionError(err_msg)

        try:
            conn = openstack.connect(
                auth_url=self.auth_url,
                project_name=self.project_name,
                username=self.username,
                password=self.password,
                user_domain_name=self.user_domain_name,
                project_domain_name=self.project_domain_name,
                region_name=self.region_name,
            )
            # Authenticate to test connection validity
            conn.authorize()
            logger.info(f"Successfully authenticated to OpenStack project '{self.project_name}' at {self.auth_url}")
            self._conn = conn
            return conn
        except SDKException as e:
            logger.error(f"OpenStack SDK Exception during connection: {e}")
            raise ConnectionError(f"Failed to connect to OpenStack: {e}")
        except Exception as e:
            logger.error(f"Unexpected connection error: {e}")
            raise ConnectionError(f"OpenStack authentication failed: {e}")


def get_openstack_connection() -> Connection:
    """Helper function to create a connection directly from environment settings."""
    client = OpenStackClient()
    return client.get_connection()
