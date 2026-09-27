"""
Alias module to support imports from modules.parser as well as modules.config_loader
"""
from modules.config_loader import load_blueprint, TenantBlueprint

__all__ = ["load_blueprint", "TenantBlueprint"]
