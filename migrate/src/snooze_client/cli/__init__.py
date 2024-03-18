'''CLI for snooze client'''

import click
import subprocess
import socket

from click_option_group import optgroup, OptionGroup

from snooze_client import Snooze

from functools import update_wrapper

from snooze_client.cli.alert import alert
from snooze_client.cli.record import record
from snooze_client.cli.snooze import snooze

@click.group()
@click.option('-s', '--server', help='URI of the Snooze server')
@click.pass_context
def snoozegroup(ctx, **kwargs):
    '''CLI for the snoozeweb server.'''
    ctx.ensure_object(dict)
    kwargs['token_to_disk'] = True
    ctx.obj['server'] = Snooze(**kwargs)

snoozegroup.add_command(alert)
snoozegroup.add_command(record)
snoozegroup.add_command(snooze)
