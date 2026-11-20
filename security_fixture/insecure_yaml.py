"""Static-analysis fixture: unsafe YAML deserialization pattern.
Do not pass untrusted input to yaml.load in real applications.
"""
import yaml

def load_config(user_supplied_yaml):
    return yaml.load(user_supplied_yaml, Loader=yaml.Loader)
