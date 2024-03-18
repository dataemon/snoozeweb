
import shlex

from click.testing import CliRunner
from snooze_client.cli.snooze import snooze
from snooze_client.cli import snoozegroup

def call_string(data, command_name='snooze_client'):
    '''
    Call a with subcommand and arguments, and will execute the expected command
    with these arguments. Understand shell syntax for argument separation.
    '''
    subcommand, *args = shlex.split(data)
    call_args(subcommand, *args, command_name=command_name)

def call_args(subcommand, *args, command_name='snooze_client'):
    '''
    Call a snooze subcommand with arguments.
    '''
    runner = CliRunner()
    snoozegroup.name = command_name
    result = runner.invoke(snoozegroup, [subcommand, *args])
    if result.exception:
        raise result.exception
    return result
