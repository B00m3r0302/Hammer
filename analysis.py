import sqlite3

class Analysis:
    def __init__(self, db_path='Valkrie.db'):
        self.db_path = db_path

    def _connect_db(self):
        return sqlite3.connect(self.db_path)

    def find_executable_discrepancies(self):
        conn = self._connect_db()
        cursor = conn.cursor()

        # Create the ExecutableDiscrepancies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ExecutableDiscrepancies (
                id INTEGER PRIMARY KEY,
                FileName TEXT NOT NULL,
                FilePath TEXT NOT NULL,
                md5Hash TEXT NOT NULL,
                Table TEXT NOT NULL
            )
        ''')

        self._compare_tables(cursor, 'BaselineExecutables', 'CurrentExecutables', ['FileName', 'FilePath', 'md5Hash'], 'ExecutableDiscrepancies')
        
        conn.commit()
        conn.close()

    def find_account_discrepancies(self):
        conn = self._connect_db()
        cursor = conn.cursor()

        # Create the AccountDiscrepancies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS AccountDiscrepancies (
                id INTEGER PRIMARY KEY,
                UserName TEXT NOT NULL,
                LastLogon TEXT,
                Table TEXT NOT NULL
            )
        ''')

        self._compare_tables(cursor, 'BaselineAccounts', 'CurrentAccounts', ['UserName', 'LastLogon'], 'AccountDiscrepancies')
        
        conn.commit()
        conn.close()

    def _compare_tables(self, cursor, table1, table2, columns, discrepancy_table):
        # Find discrepancies in table1 not in table2
        columns_str = ', '.join(columns)
        placeholders = ', '.join(['?'] * len(columns))
        query = f'''
            INSERT INTO {discrepancy_table} ({columns_str}, Table)
            SELECT {columns_str}, '{table1}'
            FROM {table1}
            WHERE NOT EXISTS (
                SELECT 1 FROM {table2} WHERE
                { ' AND '.join([f"{table1}.{col} = {table2}.{col}" for col in columns]) }
            )
        '''
        cursor.execute(query)

        # Find discrepancies in table2 not in table1
        query = f'''
            INSERT INTO {discrepancy_table} ({columns_str}, Table)
            SELECT {columns_str}, '{table2}'
            FROM {table2}
            WHERE NOT EXISTS (
                SELECT 1 FROM {table1} WHERE
                { ' AND '.join([f"{table2}.{col} = {table1}.{col}" for col in columns]) }
            )
        '''
        cursor.execute(query)
        
    def get_discrepancies():
        analysis.find_executable_discrepancies()
        analysis.find_account_discrepancies()

if __name__ == "__main__":
    analysis = Analysis()
    analysis.get_discrepancies()

