import psycopg2
import pandas as pd

class Connection:
    def __init__(self, host, port, user, password, database):
        self.constr = f'postgresql://{user}:{password}@{host}:{port}/{database}'
        self.cn = None
        
    def connect(self):
        if self.cn:
            return False
        
        self.cn = psycopg2.connect(self.constr, application_name='jupyter')
        self.cn.autocommit = True
        return True
    
    def __del__(self):
        self.close()
        
    def close(self):
        if self.cn is not None:
            self.cn.close()
            self.cn = None
            
    def cursor(self):
        self.connect()
        return self.cn.cursor()
    
    def query(self, sql):
        try:
            with self.cursor() as cur:
                #cur.execute("SET statement_timeout TO '600s'")
                cur.execute(sql)
                
                if cur.statusmessage.split()[0].upper() in ['SELECT', 'EXPLAIN', 'SHOW']:
                    res = cur.fetchall()
                    colnames = [desc[0] for desc in cur.description]
                    res = pd.DataFrame(res, columns=colnames)
                else:
                    res = cur.statusmessage
            self.close()
            return res
        except:
            self.cn.rollback()
            raise
            
    def show_index(self, table):
        return self.query(f'''
        SELECT tablename, indexname, indexdef
        FROM pg_indexes
        WHERE tablename='{table}'
        '''
        )

    
    
# cn = Connection(host='', port=5432, user='', password='', database='')
# cn.query('select 1')