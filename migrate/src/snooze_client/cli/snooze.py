'''Create snooze entry'''

import click
import json

from snooze_client.cli.utils import pass_server
from snooze_client.time_constraints import Weekday, Datetime, Time, Constraints

def parse_constraints(weekdays, datetimes, times):
    '''Parse a timeconstraint argument (repeatable)'''
    constraints = []
    if weekdays:
        constraints.append(Weekday(*weekdays))
    for datetime in datetimes:
        constraints.append(Datetime(*datetime))
    for time in times:
        constraints.append(Time(*time))
    return Constraints(*constraints)

def parse_condition(arg):
    '''Parse a condition argument'''
    return json.loads(arg)

@click.command()
@click.argument('name')
@click.option('-q', '--ql', default=None, type=str, help='Snooze query language representing the condition (Optional)')
@click.option('-c', '--condition', default=None, type=str, help='JSON representing the condition (Optional)')
@click.option('-w', '--weekdays', type=str, multiple=True, help='Weekday constraint')
@click.option('-d', '--datetimes', type=(str,str), multiple=True, help='Datetime constraint')
@click.option('-t', '--times', type=(str,str), multiple=True, help='Time constraint')
@pass_server
def snooze(server, name, ql, condition, weekdays, datetimes, times):
    '''
    Create a snooze entry
    '''
    constraints = parse_constraints(weekdays, datetimes, times)
    if condition:
        condition = parse_condition(condition)
    server.snooze(name, condition, ql, constraints)
