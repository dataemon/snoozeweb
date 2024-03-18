'''Login'''

import click

from snooze_client.cli import snoozegroup
from snooze_client.cli.utils import pass_server

@snoozegroup.command()
@click.option('--auth-method', '-A', type=click.Choice(['local', 'ldap', 'jwt']), help='Authentication method to use.')
@pass_server
def login(server):
    pass
