'''Module for CLI implementation of /api/record endpoint'''

import click
import json

from click_option_group import optgroup
from snooze_client.cli.utils import pass_server

def print_records(records):
    '''Print records in a human readable format'''
    for rec in records:
        line = "{} {} {} {} {}".format(
            rec['timestamp'],
            rec['host'],
            rec['process'],
            rec['severity'],
            rec['message'],
        )
        print(line)

@click.command()
@optgroup.group('Record options', help='Options related to the record')
@optgroup.option('-q', '--ql', type=str, default=None, help='The search of the record (in snooze query langugage)')
@optgroup.option('-S', '--search', type=str, default=None, help='The search of the record (in JSON)')
@pass_server
def record(server, ql, search):
    '''Display records based on a query'''
    args = {}
    if search:
        args['search'] = json.loads(search)
    if ql:
        args['ql'] = ql
    records = server.record(**args)
    print_records(records)
