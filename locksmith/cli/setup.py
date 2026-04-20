"""locksmith-setup — generate an RSA keypair for the license server."""

from __future__ import annotations

import click

from locksmith.core.keys import generate_keypair, save_keypair


@click.command("locksmith-setup")
@click.option(
    "--bits",
    default=4096,
    show_default=True,
    help="RSA key size in bits. 4096 recommended for new deployments.",
)
@click.option(
    "--out-dir",
    default="keys",
    show_default=True,
    help="Directory to write privkey.pem and pubkey.pem.",
)
def main(bits: int, out_dir: str) -> None:
    """Generate a new RSA keypair for the Locksmith license server.

    This is a one-time operation. Keep privkey.pem secure and never commit it
    to source control. Distribute pubkey.pem with your application.
    """
    click.echo(f"Generating {bits}-bit RSA keypair. This may take a few minutes...")
    pubkey, privkey = generate_keypair(bits)
    priv_path, pub_path = save_keypair(pubkey, privkey, out_dir)

    click.echo(f"  Private key : {priv_path}")
    click.echo(f"  Public key  : {pub_path}")
    click.secho(
        "\nDone. Keep privkey.pem secret. Never commit it to source control.",
        fg="green",
    )
