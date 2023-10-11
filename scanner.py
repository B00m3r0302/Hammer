import os
import hashlib
import sqlite3
import win32net
import win32netcon
import winreg
import datetime
import subprocess
from logger import Logger
from actions import Actions

class Scanner:

    def __init__(self, database_path):
        self.database_path = database_path
        self.logger = Logger()
        self.actions = Actions()
        self.setup_database()

    def setup_database(self):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                           CREATE TABLE IF NOT EXISTS BaselineExecutables (
                               id INTEGER PRIMARY KEY,
                               FileName TEXT NOT NULL,
                               FilePath TEXT NOT NULL,
                               md5Hash TEXT NOT NULL
                            )
                        ''')
            conn.commit()

            cursor.execute('''
                            CREATE TABLE IF NOT EXISTS ExecutableDiscrepancies (
                                id INTEGER PRIMARY KEY,
                                FileName TEXT NOT NULL,
                                FilePath TEXT NOT NULL,
                                md5Hash TEXT
                            )
                        ''')
            conn.commit()
            
            cursor.execute('''
                            CREATE TABLE IF NOT EXISTS BaselineAccounts (
                                id INTEGER PRIMARY KEY,
                                UserName TEXT NOT NULL,
                                AccountCreationDate TEXT
                            )
                        ''')
            conn.commit()
            
            cursor.execute('''
                            CREATE TABLE IF NOT EXISTS AccountDiscrepancies (
                                id INTEGER PRIMARY KEY,
                                UserName TEXT NOT NULL,
                                AccountCreationDate TEXT
                            )
                        ''')
            conn.commit()

            cursor.execute('''
                           CREATE TABLE IF NOT EXISTS autoruns (
                               id INTEGER PRIMARY KEY,
                               name TEXT NOT NULL,
                               value Text NOT NULL
                            )
                        ''')
            conn.commit()
            
            cursor.execute('''
                           CREATE TABLE IF NOT EXISTS CurrentConnections (
                               id INTEGER PRIMARY KEY,
                               local_ip TEXT NOT NULL,
                               local_port INTEGER NOT NULL,
                               remote_ip TEXT NOT NULL,
                               remote_port INTEGER NOT NULL
                            )
                        ''')
            conn.commit()
            
            cursor.execute('''
                           CREATE TABLE IF NOT EXISTS TrustedConnections (
                               id INTEGER PRIMARY KEY,
                               IP_Address TEXT NOT NULL
                            )
                        ''')
            conn.commit()
            
            cursor.execute ('''
                            CREATE TABLE IF NOT EXISTS BlockedConnections (
                                id INTEGER PRIMARY KEY,
                                IP_Address TEXT NOT NULL
                            )
                        ''')
            conn.commit()
            
    def compute_md5(self, file_path):
        hasher = hashlib.md5()
        with open(file_path, 'rb') as file:
            buf = file.read(65536)  # read 64K chunks
            while len(buf) > 0:
                hasher.update(buf)
                buf = file.read(65536)
        return hasher.hexdigest()
    
    def is_executable(self, file_path):
        _, ext = os.path.splitext(file_path)
        return os.path.isfile(file_path) and ext.lower() in ['.exe', '.bat', '.cmd', '.msi', '.ps1', 'py', '.vbs', '.dll']

    def BaselineExecutables_Scan(self, start_dir):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
            commit_counter = 0

            for root, dirs, files in os.walk(start_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # Check if the file is an executable accourding to the is_executable function
                        if not self.is_executable(file_path):
                            continue
                        file_hash = self.compute_md5(file_path)
                        print(f"File Name: {file}")
                        print(f"File Path: {file_path}")
                        print(f"MD5 Hash: {file_hash}")
                        print('-' * 50)
                        
                        cursor.execute('''
                                       INSERT INTO BaselineExecutables (FileName, FilePath, md5Hash)
                                       VALUES (?, ?, ?)
                        ''', (file, file_path, file_hash))
                        commit_counter += 1

                        # Commit every 100 files for more consistent saving.
                        if commit_counter >= 100:
                            conn.commit()
                            commit_counter = 0

                    except Exception as e:
                        self.logger.log(f"Error processing file: {file_path} - {str(e)}")

            # Final commit for any remaining files
            conn.commit()

    def CurrentExecutables_Scan(self, start_dir):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
            commit_counter = 0

            # Clears the existing database for new entries 
            for root, dirs, files in os.walk(start_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        if not self.is_executable(file_path):
                            continue
                        file_hash = self.compute_md5(file_path)
                        print(f"File Name: {file}")
                        print(f"File Path: {file_path}")
                        print(f"MD5 Hash: {file_hash}")
                        print('-' * 50)
                        
                        cursor.execute('''
                                       SELECT * FROM ExecutableDiscrepancies WHERE FileName = ? AND FilePath = ? and md5Hash = ? 
                        ''', (file, file_path, file_hash))
                        
                        if cursor.fetchone() is None:
                            cursor.execute('''
                                           INSERT INTO ExecutableDiscrepancies (FileName, FilePath, md5Hash)
                                           VALUES (?, ?, ?)
                            ''', (file, file_path, file_hash))
                            
                            self.actions.remove_executable(file_path)
                            
                            commit_counter += 1

                        # Commit every 100 files for more consistent saving.
                        if commit_counter >= 100:
                            conn.commit()
                            commit_counter = 0

                    except Exception as e:
                        self.logger.log(f"Error processing file: {file_path} - {str(e)}")

            # Final commit for any remaining files
            conn.commit()
            
    def get_users(self):
        users = []
        level = 3  # Using level 3 to get detailed information about the user
        resume = 0
        while True:
            (user_list, total, resume) = win32net.NetUserEnum(None, level, win32netcon.FILTER_NORMAL_ACCOUNT, resume, win32netcon.MAX_PREFERRED_LENGTH)
            users.extend(user_list)
            if not resume:
                break
        return users

    def BaselineUsers_Scan(self):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()

            for user in self.get_users():
                username = user['name']
                
                # If the Guest account is detected, delete it
                if username == "guest" or username == "Guest":
                    self.actions.remove_users(username)
                    
                # Extracting account creation approximation date
                password_age = user.get('password_age', None)
                if password_age is not None:
                    creation_date = (datetime.datetime.now() - datetime.timedelta(seconds=password_age)).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    creation_date = None
                
                print(f"Username: {username}")
                print(f"Account Creation Approximation Date: {creation_date}")
                print('-' * 50)
                
                
                cursor.execute('''
                    INSERT INTO BaselineAccounts (UserName, AccountCreationDate)
                    VALUES (?, ?)
                ''', (username, creation_date))
                
            conn.commit()

    def CurrentUsers_Scan(self):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()

            # Clear existing records from CurrentAccounts table
            cursor.execute("DELETE FROM CurrentAccounts")
            for user in self.get_users():
                username = user['name']
                
                # If the Guest account is detected, delete it
                if username == "guest" or username == "Guest":
                    self.actions.remove_users(username)
                    
                # Extracting account creation approximation date
                password_age = user.get('password_age', None)
                if password_age is not None:
                    creation_date = (datetime.datetime.now() - datetime.timedelta(seconds=password_age)).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    creation_date = None
            
                print(f"Username: {username}")
                print(f"Account Creation Approximation Date: {creation_date}")
                print('-' * 50)

                cursor.execute('''
                               SELECT * FROM BaselineAccounts WHERE username = ? AND AccountCreationDate = ?
                ''', (username, creation_date))
                
                if cursor.fetchone() is None:
                    cursor.execute('''
                                   INSERT INTO AccountDiscrepancies (UserName, AccountCreationDate)
                                   VALUES (?, ?)
                    ''', (username, creation_date))
            
            conn.commit()
            
    def fetch_registry_keys(self, hive, subkey):
        data = []
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        data.append((name, value))
                        i += 1
                    except WindowsError:
                        break
        except FileNotFoundError:
            print(f"{subkey} not found.")
        except PermissionError:
            print(f"Permission denied accessing {subkey}. Ensure script is run with administrative permissions.")
        return data 
    
    def fetch_registry_autoruns(self):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
            
        autorun_locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\Windows\\CurrentVersion\\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\Windows\\CurrentVersion\\RunOnce"),
        ]
        all_data = []
        for hive, subkey in autorun_locations:
            data = self.fetch_registry_keys(hive, subkey)
            all_data.extend(data)
        
        cursor.execute('''
                       INSERT INTO autoruns (name, value)
                       VALUES (?, ?)
        ''', (self.fetch_registry_keys(hive, subkey)))
        conn.commit()
    # UPDATE THIS TO ADD THE ACTION INSTEAD OF THE CODE TO DELETE THE REGISTRY ENTRY
    def continuous_registry_autoruns(self):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
        autorun_locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\Windows\\CurrentVersion\\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\Windows\\CurrentVersion\\RunOnce"),
        ]
        
        for hive,subkey in autorun_locations:
            data = self.fetch_registry_keys(hive, subkey)
            
            for name, value in data:
                cursor.execute('SELECT * FROM autoruns WHERE name = ? AND value = ?', (name, value))
                if not cursor.fetchone():
                    self.actions.delete_registry_autorun(hive, subkey, name)
        
    def get_current_connections(self):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
        result = subprocess.check_output("netstat -n").decode('utf-8').split('\n')
        connections = []
        
        for line in result:
            parts = line.split()
            
            # Ensuring that  the line has enough parts to be a valid connection 
            if len(parts) >=3:
                # Extracting local IP and port
                local_ip, local_port_str = parts[1].rsplit(':', 1)
                local_port = int(local_port_str) # Converting port to an integer
                
                # Extracting remote IP and port
                remote_ip, remote_port_str = parts[2].rsplit(':', 1)
                remote_port = int(remote_port_str)
                
                # Adding tuple (local_ip, local_port, remote_ip, remote_port) to connections list
                connections.append((local_ip, local_port, remote_ip, remote_port))
                cursor.execute('''
                               INSERT INTO CurrentConnections (local_ip, local_port, remote_ip, remote_port)
                               VALUES (?, ?, ?, ?)
                ''', (local_ip, local_port, remote_ip, remote_port))
                conn.commit()
                
        return connections
          
    def Baseline_Scan(self, start_dir):
        self.logger.log("Starting baseline Executables scan...")
        self.BaselineExecutables_Scan(start_dir)
        self.logger.log("Baseline Executables scan complete.")
        
        self.logger.log("Starting baseline Users scan...")
        self.BaselineUsers_Scan()
        self.logger.log("Baseline Users scan complete.")
        
        self.logger.log("Starting baseline Autoruns scan...")
        self.fetch_registry_autoruns()
        self.logger.log("Baseline Autoruns scan complete.")
    
    def ExecutablesScan (self, start_dir):
        self.logger.log("Starting current Executables scan...")
        self.CurrentExecutables_Scan(start_dir)
        self.logger.log("Current Executables scan complete.")
        
    def Continuous_Scan(self):
        self.logger.log("Starting current Users scan...")
        self.CurrentUsers_Scan()
        self.logger.log("Current Users scan complete.")
        
        self.logger.log("Starting current Autoruns scan...")
        self.continuous_registry_autoruns()
        self.logger.log("Current Autoruns scan complete.")
        



if __name__ == "__main__":
    scanner = Scanner("GuardianAngel.db")
    scanner.Baseline_Scan()
    scanner.ExecutablesScan()
    scanner.Continuous_Scan()