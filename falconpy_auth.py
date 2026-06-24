"""FalconPy credential resolution.

Priority order:
1. Explicit CLI args (client_id + client_secret)
2. ~/.falconpy/credentials INI file (supports named profiles)
3. Environment variables (FALCON_CLIENT_ID, FALCON_CLIENT_SECRET)
"""
import configparser
import os
import sys
from pathlib import Path

_DEFAULT_CREDS_PATH = Path.home() / ".falconpy" / "credentials"


def _load_from_file(profile: str = "default",
                    config_path: Path | None = None) -> dict | None:
    path = config_path or _DEFAULT_CREDS_PATH
    if not path.exists():
        return None
    try:
        config = configparser.ConfigParser()
        config.read(path)
        if profile not in config:
            return None
        creds = {
            "client_id":     config[profile].get("client_id"),
            "client_secret": config[profile].get("client_secret"),
            "base_url":      config[profile].get("base_url", "auto"),
        }
        if (creds["client_id"] and creds["client_secret"]
                and "YOUR_CLIENT_ID_HERE" not in creds["client_id"]):
            return creds
    except Exception as e:
        print(f"Warning: error reading credentials file: {e}", file=sys.stderr)
    return None


def _load_from_env() -> dict | None:
    client_id     = os.getenv("FALCON_CLIENT_ID")
    client_secret = os.getenv("FALCON_CLIENT_SECRET")
    if client_id and client_secret:
        return {
            "client_id":     client_id,
            "client_secret": client_secret,
            "base_url":      os.getenv("FALCON_BASE_URL", "auto"),
        }
    return None


def list_profiles(config_path: Path | None = None) -> list[str]:
    """Return profile names from the credentials file."""
    path = config_path or _DEFAULT_CREDS_PATH
    if not path.exists():
        return []
    try:
        config = configparser.ConfigParser()
        config.read(path)
        return list(config.sections())
    except Exception:
        return []


def get_falcon_credentials(
    profile: str = "default",
    client_id: str | None = None,
    client_secret: str | None = None,
    base_url: str | None = None,
    config_path: str | None = None,
) -> dict:
    """Return credentials dict with keys client_id, client_secret, base_url.

    Raises SystemExit if no credentials are found from any source.
    """
    cfg_path = Path(config_path) if config_path else None

    if client_id and client_secret:
        return {"client_id": client_id, "client_secret": client_secret,
                "base_url": base_url or "auto"}

    for loader in (_load_from_file(profile, cfg_path), _load_from_env()):
        if loader:
            if base_url:
                loader["base_url"] = base_url
            return loader

    print("Error: No Falcon API credentials found.", file=sys.stderr)
    creds_path = cfg_path or _DEFAULT_CREDS_PATH
    print("\nPlease configure credentials using one of these methods:", file=sys.stderr)
    print(f"1. Create/edit: {creds_path}", file=sys.stderr)
    print("2. Set environment variables: FALCON_CLIENT_ID, FALCON_CLIENT_SECRET", file=sys.stderr)
    print("3. Pass --client_id and --client_secret arguments", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    print("Available profiles:", list_profiles())
    print("\nAttempting to load credentials...")
    creds = get_falcon_credentials()
    print("Successfully loaded credentials")
    print(f"  Client ID: {creds['client_id'][:8]}...")
    print(f"  Base URL: {creds['base_url']}")
