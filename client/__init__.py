"""
Fixion 2.0 Client Package
AI-Powered Malware Detection System
"""

__version__ = "2.0.0"
__author__ = "Crestal Team"

from client.config.config import FixionConfig, get_config, set_config
from client.database.local_database import LocalDatabase

__all__ = [
    'FixionConfig',
    'get_config',
    'set_config',
    'LocalDatabase',
    '__version__',
    '__author__'
]
