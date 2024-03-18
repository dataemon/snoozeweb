import sys
sys.path.insert(0, './')
from snooze_client import Snooze
import configparser
from utils import Connection
import logging


log = logging.getLogger('snooze_migrate')
log.setLevel(logging.INFO)
log.addHandler(logging.StreamHandler(sys.stderr))

def get_chunks(lst, n):
    '''Split list into chunks of equal size'''
    return [lst[i:i + n] for i in range(0, len(lst), n)]

class Migration(object):
    '''An object for migrate the old snooze filters to new SnoozeWeb'''
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read('./config/config.conf')
        self.api = Snooze()
        self.api.login()
        DATABASE_HOST = self.config.get('postgres', 'DATABASE_HOST')
        DATABASE_USERNAME = self.config.get('postgres', 'DATABASE_USERNAME')
        DATABASE_PASSWORD = self.config.get('postgres', 'DATABASE_PASSWORD')
        DATABASE_PORT = self.config.get('postgres', 'DATABASE_PORT')
        DATABASE_NAME = self.config.get('postgres', 'DATABASE_NAME')
        self.cn = Connection(host=DATABASE_HOST, port=DATABASE_PORT, user=DATABASE_USERNAME, password=DATABASE_PASSWORD, database=DATABASE_NAME)
        self.old_filters_df = self.get_old_filters()

    def get_old_filters(self):
        q = '''
        SELECT 
            *
        FROM filters
        '''
        res = self.cn.query(q)
        return res
    
    def clear_test_info(self):
        fun_pairs = [
            [self.api.fetch_rules, self.api.delete_rules],
            [self.api.fetch_snoozes, self.api.delete_snoozes],
            [self.api.fetch_notifications, self.api.delete_notifications],
            [self.api.fetch_actions, self.api.delete_actions],
        ]
        for [fetch_fun, delete_fun] in fun_pairs:
            res = fetch_fun()
            uids = [item['uid'] for item in res]
            if not uids:
                continue
            for batch_uids in get_chunks(uids, 50):
                exe_res = delete_fun(batch_uids)
                log.info(f"### {delete_fun.__name__} delete info: {exe_res}")
    
    def sync_to_snoozeweb(self):
        self.clear_test_info()
        snooze_obj_ls = []
        rule_obj_ls = []
        notifi_obj_ls = [{
            "name": f"mig_defult_notification",
            "actions": [f"[snooze_client] defult_mail"],
            "time_constraints": [{"from": "2010-01-01 00:00:00+09:00", "until": "2100-01-01 00:00:00+09:00"}],
            "condition": [
                "NOT",
                [
                    "EXISTS",
                    "ower_flag",
                    ""
                ]
            ]
        }]
        mail_obj_ls = [{
            "name": 'defult_mail',
            "host": self.config.get("mail_server", "Host"),
            "port": self.config.get("mail_server", "Port"),
            "from": self.config.get("mail_server", "From"),
            "to": self.config.get("mail_server", "To")
        }]
        mail_set = set()
        weekday_dic = {
            'Sun': 0,
            'Mon': 1,
            'Tue': 2,
            'Wed': 3,
            'Thu': 4,
            'Fri': 5,
            'Sat': 6
        }
        for i, row in self.old_filters_df.iterrows():
            filter_item = row.to_dict()
            time_constraints = {
                "datetime":[{"from": filter_item['begintime'].strftime("%Y-%m-%dT%H:%M%z"), "until": filter_item['endtime'].strftime("%Y-%m-%dT%H:%M%z")}]
            }
            if filter_item['dayofweek']:
                time_constraints.update({
                    "weekdays":[{"weekdays":[weekday_dic[wd] for wd in filter_item['dayofweek']]}]
                })
            if filter_item['has_regex']:
                condition = ["MATCHES", "raw", filter_item['string']]
            else:
                condition = ["CONTAINS", "raw", filter_item['string']]
            if filter_item['email']:
                mail_ls = filter_item['email'].split(',')
                notifi_obj_ls.append({
                    "name": f"mig_{filter_item['id']}",
                    "actions": [f"[snooze_client] {mail}" for mail in mail_ls],
                    "time_constraints": time_constraints,
                    "condition": condition,
                    "comment": filter_item['reason']
                })
                ower = "developer"
            else:
                mail_ls = []
                snooze_obj_ls.append({
                    "name": f"mig_{filter_item['id']}",
                    "time_constraints": time_constraints,
                    "condition": condition,
                    "comment": filter_item['reason']
                })
                ower = "snooze"
            rule_obj_ls.append({
                "name": f"mig_{filter_item['id']}",
                "modifications":[["SET", "ower_flag", ower]],
                "condition": condition,
                "comment": filter_item['reason']
            })
            mail_set = mail_set.union(set(mail_ls))
        mail_obj_ls += [{
            "name": mail,
            "host": self.config.get("mail_server", "Host"),
            "port": self.config.get("mail_server", "Port"),
            "from": self.config.get("mail_server", "From"),
            "to": mail
        } for mail in mail_set]
        self.api.action_batch(mail_obj_ls)
        log.info(f"### add actions count: {len(mail_obj_ls)}")
        self.api.rule_batch(rule_obj_ls)
        log.info(f"### add rules count: {len(rule_obj_ls)}")
        self.api.snooze_batch(snooze_obj_ls)
        log.info(f"### add snoozes count: {len(snooze_obj_ls)}")
        self.api.notification_batch(notifi_obj_ls)
        log.info(f"### add notifications count: {len(notifi_obj_ls)}")

def main():
    log.info("$$$ start to migrate......")
    mig = Migration()
    log.info(f"### Old snooze filters count: {len(mig.old_filters_df)}")
    mig.sync_to_snoozeweb()

if __name__ == '__main__':
    main()