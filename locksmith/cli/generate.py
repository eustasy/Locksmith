"""locksmith-issue — generate and sign a new license file."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click

from locksmith.core.config import settings
from locksmith.core.keys import FileSigner
from locksmith.core.license import (
    Entitlement,
    License,
    LicenseRequest,
    TimePolicy,
)
from locksmith.core.signer import sign_license


@click.command("locksmith-issue")
@click.option("--email", default=None, help="Licensee email address.")
# ---- Time ----
@click.option(
    "--expires-days",
    default=0,
    show_default=True,
    help="Days until expiry. Omit (or use 0) for a perpetual license.",
)
# ---- Version ----
@click.option(
    "--version-policy",
    type=click.Choice(["any", "maintenance", "specific"]),
    default="any",
    show_default=True,
    help="Version policy: any, maintenance (major version only), or specific (exact).",
)
@click.option(
    "--major-version",
    type=int,
    default=None,
    help="Major version number (required for --version-policy maintenance).",
)
@click.option(
    "--locked-version",
    default=None,
    help="Exact version string (required for --version-policy specific).",
)
# ---- Edition / Platform ----
@click.option(
    "--editions",
    default=None,
    help="Comma-separated allowed edition names, e.g. 'pro,enterprise'. Omit for any.",
)
@click.option(
    "--platforms",
    default=None,
    help="Comma-separated allowed OS values, e.g. 'windows,macos'. Omit for any.",
)
# ---- Restriction ----
@click.option(
    "--restriction",
    type=click.Choice(["activations", "users", "floating"]),
    default=None,
    help="Restriction mode: activations (machines), users, or floating (concurrent).",
)
@click.option(
    "--activation-limit",
    type=int,
    default=None,
    help="Max distinct machines (activations mode).",
)
@click.option(
    "--user-limit",
    type=int,
    default=None,
    help="Max distinct user principals (users mode).",
)
@click.option(
    "--concurrent-limit",
    type=int,
    default=None,
    help="Max concurrent sessions (floating mode).",
)
# ---- Entitlements ----
@click.option(
    "--app-id",
    default=None,
    help=(
        "App ID for a single-app entitlement (e.g. 'com.example.myapp'). "
        "For bundles use --entitlements-file."
    ),
)
@click.option(
    "--entitlement-editions",
    default=None,
    help="Comma-separated editions for --app-id entitlement.",
)
@click.option(
    "--entitlement-min-version",
    default=None,
    help="Minimum inclusive app version for --app-id entitlement.",
)
@click.option(
    "--entitlement-max-version",
    default=None,
    help="Maximum inclusive app version for --app-id entitlement.",
)
@click.option(
    "--entitlement-platforms",
    default=None,
    help="Comma-separated platforms for --app-id entitlement.",
)
@click.option(
    "--entitlement-seats",
    type=int,
    default=None,
    help="Seat override for --app-id entitlement.",
)
@click.option(
    "--entitlements-file",
    default=None,
    type=click.Path(exists=True),
    help=(
        "JSON file containing a list of entitlement objects. "
        "Overrides all single-entitlement options."
    ),
)
# ---- Common ----
@click.option(
    "--request-file",
    default=None,
    type=click.Path(exists=True),
    help="Import email / machine_id from a customer .lsreq file.",
)
@click.option(
    "--privkey",
    default=None,
    type=click.Path(exists=True),
    help="Path to privkey.pem. Defaults to LOCKSMITH_PRIVKEY_PATH.",
)
@click.option("--out", default=None, help="Output .lic file path.")
def main(
    email: str | None,
    expires_days: int,
    version_policy: str,
    major_version: int | None,
    locked_version: str | None,
    editions: str | None,
    platforms: str | None,
    restriction: str | None,
    activation_limit: int | None,
    user_limit: int | None,
    concurrent_limit: int | None,
    app_id: str | None,
    entitlement_editions: str | None,
    entitlement_min_version: str | None,
    entitlement_max_version: str | None,
    entitlement_platforms: str | None,
    entitlement_seats: int | None,
    entitlements_file: str | None,
    request_file: str | None,
    privkey: str | None,
    out: str | None,
) -> None:
    """Issue a signed license file (.lic).

    \b
    Examples
    --------
    # Perpetual, any version, any edition — no restriction:
      locksmith-issue --email user@co.com

    # 1-year limited, Pro/Enterprise only, Windows and Linux, max 3 activations:
      locksmith-issue --email user@co.com --expires-days 365 \\
        --editions pro,enterprise --platforms windows,linux \\
        --restriction activations --activation-limit 3

    # Maintenance — covers major version 2.x, max 5 activations:
      locksmith-issue --email user@co.com \\
        --version-policy maintenance --major-version 2 \\
        --restriction activations --activation-limit 5

    # Floating — max 10 concurrent sessions:
      locksmith-issue --email user@co.com \\
        --restriction floating --concurrent-limit 10

    # Bundle — multiple applications from a JSON file:
      locksmith-issue --email user@co.com --entitlements-file bundle.json
    """
    if request_file:
        req = LicenseRequest.from_file(request_file)
        email = email or req.email
        if not app_id:
            app_id = req.app_id

    if not email:
        raise click.UsageError("--email is required (or provide --request-file).")

    # Build entitlements list
    entitlements: list[Entitlement] = []

    if entitlements_file:
        raw = json.loads(Path(entitlements_file).read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise click.UsageError("--entitlements-file must contain a JSON array.")
        entitlements = [Entitlement.from_dict(e) for e in raw]
    elif app_id:
        entitlements = [
            Entitlement(
                app_id=app_id,
                editions=[e.strip() for e in entitlement_editions.split(",")]
                if entitlement_editions
                else None,
                min_version=entitlement_min_version,
                max_version=entitlement_max_version,
                platforms=[p.strip() for p in entitlement_platforms.split(",")]
                if entitlement_platforms
                else None,
                seats=entitlement_seats,
            )
        ]

    privkey_path = Path(privkey) if privkey else settings.privkey_path
    pubkey_path = settings.pubkey_path
    signer = FileSigner.from_files(pubkey_path=pubkey_path, privkey_path=privkey_path)

    now = datetime.now(timezone.utc)
    time_policy = TimePolicy.LIMITED if expires_days > 0 else TimePolicy.PERPETUAL

    lic = License(
        license_id=str(uuid.uuid4()),
        email=email,
        issued_at=now,
        valid_from=now,
        time_policy=time_policy,
        expires_at=(now + timedelta(days=expires_days)) if expires_days > 0 else None,
        version_policy=version_policy,
        major_version=major_version,
        locked_version=locked_version,
        editions=[e.strip() for e in editions.split(",")] if editions else None,
        platforms=[p.strip() for p in platforms.split(",")] if platforms else None,
        restriction=restriction,
        activation_limit=activation_limit,
        user_limit=user_limit,
        concurrent_limit=concurrent_limit,
        entitlements=entitlements,
    )

    asyncio.run(sign_license(lic, signer))

    safe_email = email.replace("@", "_").replace(".", "_")
    out_path = out or f"{safe_email}_{lic.license_id[:8]}.lic"
    lic.to_file(out_path)

    click.secho(f"License written to: {out_path}", fg="green")
    click.echo(f"  ID              : {lic.license_id}")
    click.echo(f"  Email           : {lic.email}")
    click.echo(
        f"  Time            : {lic.time_policy.value}"
        + (f" (expires {lic.expires_at.date()})" if lic.expires_at else "")
    )
    click.echo(
        f"  Version         : {lic.version_policy.value}"
        + (f" (major {lic.major_version})" if lic.major_version is not None else "")
        + (f" (locked {lic.locked_version})" if lic.locked_version else "")
    )
    click.echo(
        f"  Editions        : {', '.join(lic.editions) if lic.editions else 'any'}"
    )
    click.echo(
        f"  Platforms       : {', '.join(lic.platforms) if lic.platforms else 'any'}"
    )
    if lic.restriction:
        mode = lic.restriction.value
        limit_val = lic.activation_limit or lic.user_limit or lic.concurrent_limit
        click.echo(f"  Restriction     : {mode} (limit: {limit_val})")
    else:
        click.echo("  Restriction     : none")
    if lic.entitlements:
        click.echo(f"  Entitlements    : {len(lic.entitlements)} app(s)")
        for ent in lic.entitlements:
            parts = [f"    [{ent.app_id}]"]
            if ent.editions:
                parts.append(f"editions={','.join(ent.editions)}")
            if ent.min_version or ent.max_version:
                parts.append(
                    f"versions={ent.min_version or '*'}..{ent.max_version or '*'}"
                )
            if ent.platforms:
                parts.append(f"platforms={','.join(ent.platforms)}")
            if ent.seats:
                parts.append(f"seats={ent.seats}")
            click.echo("  " + " ".join(parts))
    else:
        click.echo("  Entitlements    : none (applies to all applications)")
