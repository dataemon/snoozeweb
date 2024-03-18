'''
A module with utils functions to make the creation of time constraints
easier for python developers.
'''

import locale
import calendar

class Constraint:
    def to_time_constraint(self):
        return {self.key: self.to_object()}
    def to_object(self):
        return self.object

class Constraints(Constraint):
    def __init__(self, *constraints):
        '''
        Create a time constraint based on multiple time constraints.
        Example:
        Constraints(Weekday('Saturday'), Time(time_from='09:00', time_until='10:00'))
        '''
        self.constraints = constraints

    def to_time_constraint(self):
        time_constraint = {}
        for constraint in self.constraints:
            if isinstance(constraint, Constraint):
                key = constraint.key
                if not time_constraint.get(key):
                    time_constraint[key] = []
                time_constraint[key].append(constraint.to_object())
            else:
                raise Exception("{} does not inherit Constraint".format(constraint))
        return time_constraint

class Weekday(Constraint):
    def __init__(self, *weekdays, locale_str='ja_JP.utf8'):
        '''
        Create a time constraint based on weekdays.
        Example 1:
        Weekday('Saturday', 'Sunday')
        Example 2:
        Weekday('Lundi', locale='fr_FR')
        Example 3:
        Weekday(6, 7)
        '''
        self.weekdays = []
        self.object = {}
        self.key = 'weekdays'
        locale.setlocale(locale.LC_ALL, locale_str)
        day_names = list(calendar.day_name)
        day_abbrs = list(calendar.day_abbr)
        for weekday in weekdays:
            if isinstance(weekday, int) and 1 <= weekday <= 7:
                self.weekdays.append(weekday)
            if weekday in day_names:
                index = day_names.index(weekday)
                self.weekdays.append(index + 1)
                break
            elif weekday in day_abbrs:
                index = day_abbrs.index(weekday)
                self.weekdays.append(index + 1)
                break
            else:
                raise Exception("{} is not a valid weekday".format(weekday))
        self.object['weekdays'] = self.weekdays

class Time(Constraint):
    def __init__(self, time_from=None, time_until=None):
        '''
        Create a time constraint.
        Example:
        Time(time_from='09:00', time_until='10:00')
        '''
        self.object = {}
        self.key = 'time'
        if time_from:
            self.object['from'] = time_from
        if time_until:
            self.object['until'] = time_until

class Datetime(Constraint):
    def __init__(self, datetime_from=None, datetime_until=None):
        '''
        Create a datetime constraint.
        Example:
        Datetime(datetime_from='2021-07-01T12:00:00', datetime_until='2021-08-31T12:00:00')
        '''
        self.object = {}
        self.key = 'datetime'
        if datetime_from:
            self.object['from'] = datetime_from
        if datetime_until:
            self.object['until'] = datetime_until
