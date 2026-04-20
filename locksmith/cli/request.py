"""locksmith-request — generate a license request file (.lsreq) to send to the vendor.

Run this on the customer's machine. The machine ID is computed automatically
and embedded in the request file so the vendor can issue an activation-restricted
license without asking for it manually.
"""

from __future__ import annotations


import click

from locksmith.core.license import LicenseRequest
from locksmith.core.machine import compute_machine_id


@click.command("locksmith-request")
@click.option("--email", required=True, help="Your email address.")
@click.option(
    "--app-id",
    default=None,
    help="Application ID you are requesting a license for (e.g. 'com.example.myapp').",
)
@click.option(
    "--app-version",
    required=True,
    help="The version of the application you are licensing (e.g. '2.1.0').",
)
@click.option("--out", default=None, help="Output .lsreq file path.")
def main(email: str, app_id: str | None, app_version: str, out: str | None) -> None:
    """Generate a license request file (.lsreq) to send to your software vendor."""
    machine_id: str | None = None
    try:
        machine_id = compute_machine_id()
        click.echo(f"Machine ID: {machine_id}")
    except RuntimeError as exc:
        click.secho(
            f"Warning: could not compute machine ID: {exc}", fg="yellow", err=True
        )

    req = LicenseRequest.new(
        email=email,
        machine_id=machine_id,
        app_id=app_id,
        app_version=app_version,
    )

    safe_email = email.replace("@", "_").replace(".", "_")
    out_path = out or f"{safe_email}.lsreq"
    req.to_file(out_path)

    click.secho(f"Request written to: {out_path}", fg="green")
    click.echo("Send this file to your software vendor to receive a license.")
