import yaml
import os
from pathlib import Path

def load_config(config_path=None):
    """Load configuration from yaml file"""
    if not config_path:
        # Default to config.yaml in the package root or user's home
        # For this setup, we'll look relative to this file's parent (utils) -> parent (incident_scripts) -> config.yaml
        base_path = Path(__file__).parent.parent
        config_path = base_path / 'config.yaml'
    
    if not os.path.exists(config_path):
        return {}
        
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return {}
