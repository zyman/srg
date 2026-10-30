"""One SSH trust boundary for fixed reader and action commands."""
from pathlib import Path
import re

HOST = r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}"
USER = r"[a-z][a-z0-9_-]{0,31}"
CREDENTIAL = r"[a-z][a-z0-9-]{0,63}"


def validate_endpoint(config):
    for key, pattern, default in (("host", HOST, ""), ("user", USER, "agentops"),
                                  ("credential", CREDENTIAL, "")):
        value = config.get(key, default)
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError("invalid SSH endpoint")
    if not isinstance(config.get("known_hosts"), str) or not Path(config["known_hosts"]).is_absolute():
        raise ValueError("managed host keys required")


def command(config, credentials, operation):
    validate_endpoint(config)
    if operation not in ("health", "action"):
        raise ValueError("unsupported SSH command")
    return ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=yes",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UserKnownHostsFile=" + config["known_hosts"],
            "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR", "-i",
            str(Path(credentials) / config["credential"]),
            config.get("user", "agentops") + "@" + config["host"], operation]
