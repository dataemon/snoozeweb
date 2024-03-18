'''Utils for CLI'''

import click

from functools import update_wrapper

def pass_server(f):
    '''Pass the snooze server from the click context'''
    @click.pass_context
    def wrapper(ctx, *args, **kwargs):
        return ctx.invoke(f, ctx.obj['server'], *args, **kwargs)
    return update_wrapper(wrapper, f)

def parse_kv(keyvalues):
    '''Parse list of string in the key=value format and return a dict'''
    record = {}
    for keyvalue in keyvalues:
        if '=' not in keyvalue:
            raise ValueError("Options must be of format key=value")
        key, value = keyvalue.split('=', 1)
        record[key] = value
    return record
