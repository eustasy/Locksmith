"""locksmith-verify — offline license verification (development / support tool)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from locksmith.core.config import settings
from locksmith.core.keys import FileSigner
from locksmith.core.license import License
from locksmith.core.signer import LicenseError, validate_license


@click.command("locksmith-verify")
@click.option(
    "--license",
    "license_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to the .lic file to verify.",
)
@click.option(
    "--pubkey",
    default=None,
    type=click.Path(exists=True),
    help="Path to pubkey.pem. Defaults to LOCKSMITH_PUBKEY_PATH.",
)
@click.option(
    "--app-version",
    default=None,
    help="Application version string (e.g. '2.1.0'). Required for maintenance licenses.",
)
def main(license_file: str, pubkey: str | None, app_version: str | None) -> None:
    """Verify a .lic file offline using only the public key."""
    pubkey_path = Path(pubkey) if pubkey else settings.pubkey_path
    signer = FileSigner.from_files(pubkey_path=pubkey_path)

    lic = License.from_file(license_file)

    try:
        asyncio.run(
            validate_license(
                lic,
                signer,
                app_version=app_version,
            )
        )
        click.secho("License is VALID.", fg="green")
        click.echo(f"  ID              : {lic.license_id}")
        click.echo(f"  Email           : {lic.email}")
        click.echo(f"  Time            : {lic.time_policy.value}")
        click.echo(f"  Version         : {lic.version_policy.value}")
        click.echo(
            f"  Restriction     : {lic.restriction.value if lic.restriction else 'none'}"
        )
        click.echo(
            f"  Expires         : {lic.expires_at.isoformat() if lic.expires_at else 'never'}"
        )
    except LicenseError as exc:
        click.secho(f"License is INVALID: {exc}", fg="red")
        sys.exit(1)
