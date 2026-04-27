"""FalconPy Credential Manager

This module handles loading CrowdStrike Falcon API credentials from multiple sources:
1. ~/.falconpy/credentials file (preferred)
2. Environment variables (FALCON_CLIENT_ID, FALCON_CLIENT_SECRET)
3. Command line arguments

Usage:
    from falconpy_auth import get_falcon_credentials

    creds = get_falcon_credentials()
    # or with a specific profile
    creds = get_falcon_credentials(profile='production')
"""

import os
import sys
import configparser
from pathlib import Path
from typing import Dict, Optional


class CredentialManager:
    """Manages FalconPy credentials from multiple sources."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the credential manager.

        Args:
            config_path: Path to credentials file. Defaults to ~/.falconpy/credentials
        """
        if config_path:
            self.config_path = Path(config_path)
        else:
            self.config_path = Path.home() / '.falconpy' / 'credentials'

    def load_from_file(self, profile: str = 'default') -> Optional[Dict[str, str]]:
        """Load credentials from config file.

        Args:
            profile: Profile name to load (default: 'default')

        Returns:
            Dictionary with client_id, client_secret, and base_url or None
        """
        if not self.config_path.exists():
            return None

        try:
            config = configparser.ConfigParser()
            config.read(self.config_path)

            if profile not in config:
                return None

            creds = {
                'client_id': config[profile].get('client_id'),
                'client_secret': config[profile].get('client_secret'),
                'base_url': config[profile].get('base_url', 'auto')
            }

            # Check if credentials are set (not placeholder values)
            if (creds['client_id'] and
                creds['client_secret'] and
                'YOUR_CLIENT_ID_HERE' not in creds['client_id']):
                return creds

        except Exception as e:
            print(f"Warning: Error reading credentials file: {e}", file=sys.stderr)

        return None

    def load_from_env(self) -> Optional[Dict[str, str]]:
        """Load credentials from environment variables.

        Returns:
            Dictionary with client_id, client_secret, and base_url or None
        """
        client_id = os.getenv('FALCON_CLIENT_ID')
        client_secret = os.getenv('FALCON_CLIENT_SECRET')
        base_url = os.getenv('FALCON_BASE_URL', 'auto')

        if client_id and client_secret:
            return {
                'client_id': client_id,
                'client_secret': client_secret,
                'base_url': base_url
            }

        return None

    def get_credentials(self,
                       profile: str = 'default',
                       client_id: Optional[str] = None,
                       client_secret: Optional[str] = None,
                       base_url: Optional[str] = None) -> Dict[str, str]:
        """Get credentials from the first available source.

        Priority order:
        1. Explicitly provided arguments
        2. Config file
        3. Environment variables

        Args:
            profile: Profile name to load from config file
            client_id: Explicit client ID (highest priority)
            client_secret: Explicit client secret (highest priority)
            base_url: Explicit base URL (highest priority)

        Returns:
            Dictionary with client_id, client_secret, and base_url

        Raises:
            SystemExit: If no credentials are found
        """
        # Check explicit arguments first
        if client_id and client_secret:
            return {
                'client_id': client_id,
                'client_secret': client_secret,
                'base_url': base_url or 'auto'
            }

        # Try config file
        creds = self.load_from_file(profile)
        if creds:
            # Override with explicit values if provided
            if base_url:
                creds['base_url'] = base_url
            return creds

        # Try environment variables
        creds = self.load_from_env()
        if creds:
            # Override with explicit values if provided
            if base_url:
                creds['base_url'] = base_url
            return creds

        # No credentials found
        print("Error: No Falcon API credentials found.", file=sys.stderr)
        print("\nPlease configure credentials using one of these methods:", file=sys.stderr)
        print(f"1. Create/edit: {self.config_path}", file=sys.stderr)
        print("2. Set environment variables: FALCON_CLIENT_ID, FALCON_CLIENT_SECRET", file=sys.stderr)
        print("3. Pass --client_id and --client_secret arguments", file=sys.stderr)
        sys.exit(1)

    def list_profiles(self) -> list:
        """List available profiles in the credentials file.

        Returns:
            List of profile names
        """
        if not self.config_path.exists():
            return []

        try:
            config = configparser.ConfigParser()
            config.read(self.config_path)
            return list(config.sections())
        except Exception:
            return []


def get_falcon_credentials(profile: str = 'default',
                          client_id: Optional[str] = None,
                          client_secret: Optional[str] = None,
                          base_url: Optional[str] = None,
                          config_path: Optional[str] = None) -> Dict[str, str]:
    """Convenience function to get Falcon credentials.

    Args:
        profile: Profile name to load from config file (default: 'default')
        client_id: Explicit client ID (overrides file/env)
        client_secret: Explicit client secret (overrides file/env)
        base_url: Explicit base URL (overrides file/env)
        config_path: Path to credentials file (default: ~/.falconpy/credentials)

    Returns:
        Dictionary with 'client_id', 'client_secret', and 'base_url' keys

    Example:
        creds = get_falcon_credentials()
        falcon = Hosts(**creds)
    """
    manager = CredentialManager(config_path)
    return manager.get_credentials(profile, client_id, client_secret, base_url)


if __name__ == "__main__":
    # Test the credential manager
    manager = CredentialManager()
    print("Available profiles:", manager.list_profiles())
    print("\nAttempting to load credentials...")
    creds = manager.get_credentials()
    print(f"Successfully loaded credentials")
    print(f"  Client ID: {creds['client_id'][:8]}...")
    print(f"  Base URL: {creds['base_url']}")
