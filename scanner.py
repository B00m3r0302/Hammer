import os
import hashlib
import sqlite3
import win32net
import win32netcon
import winreg
import datetime
import subprocess
import sched
import time
from logger import Logger
from actions import Actions
from menu import Menu

class Scanner:

    def __init__(self, database_path):
        database_path = "GuardianAngel.db"
        self.database_path = database_path
        self.logger = Logger()
        self.actions = Actions()
        self.setup_database()
        self.s = sched.scheduler(time.time, time.sleep)
        self.menu = Menu()

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
                        # Check if the file is an executable according to the is_executable function
                        if not self.is_executable(file_path):
                            continue
                        file_hash = self.compute_md5(file_path)
                        self.logger.log(f"File Name: {file}")
                        self.logger.log(f"File Path: {file_path}")
                        self.logger.log(f"MD5 Hash: {file_hash}")
                        self.logger.log('-' * 50)
                        
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
                        self.logger.log(f"File Name: {file}")
                        self.logger.log(f"File Path: {file_path}")
                        self.logger.log(f"MD5 Hash: {file_hash}")
                        self.logger.log('-' * 50)
                        
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
    
    def connection_handler(self):
        self.get_current_connections()
        
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
            
        cursor.execute("SELECT local_ip, remote_ip FROM CurrentConnections")
        current_connections = [ip for row in cursor.fetchall() for ip in row]
        trusted_IP = self.actions.fetch_trusted_IPs()
        for ip in current_connections:
            if ip not in trusted_IP:
                self.logger.log(f"Blocking IP {ip}")
                self.actions.block_IP(ip)

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
                
                self.logger.log(f"Username: {username}")
                self.logger.log(f"Account Creation Approximation Date: {creation_date}")
                self.logger.log('-' * 50)
                
                
                cursor.execute('''
                    INSERT INTO BaselineAccounts (UserName, AccountCreationDate)
                    VALUES (?, ?)
                ''', (username, creation_date))
                
            conn.commit()

    def CurrentUsers_Scan(self):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()

            # Clear existing records from CurrentAccounts table
            cursor.execute("SELECT UserName FROM BaselineAccounts")
            baseline_users = [row[0] for row in cursor.fetchall()]
            
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
            
                self.logger.log(f"Username: {username}")
                self.logger.log(f"Account Creation Approximation Date: {creation_date}")
                self.logger.log('-' * 50)
                
                if username not in baseline_users:
                    self.actions.remove_users(username)
                    self.logger.log(f"User '{username}' has been disabled")
                    continue

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
        
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
            for name, value in all_data:
                cursor.execute('''
                               INSERT INTO autoruns (name, value)
                               VALUES (?, ?)
                ''', (name, value))
                conn.commit()

    # UPDATE THIS TO ADD THE ACTION INSTEAD OF THE CODE TO DELETE THE REGISTRY ENTRY
    def continuous_registry_autoruns(self):
        autorun_locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\Windows\\CurrentVersion\\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\Windows\\CurrentVersion\\RunOnce"),
        ]
        
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
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
            print(parts)
            
            # Ensuring that  the line has enough parts to be a valid connection
            if len(parts) < 3 or not (parts[0] == 'TCP' or parts[0] == 'UDP'):
                continue
            try:
                # Extracting local IP and port
                local_ip, local_port_str = parts[1].rsplit(':', 1)
                local_port = int(local_port_str) # Converting port to an integer
                
                # Extracting remote IP and port
                remote_ip, remote_port_str = parts[2].rsplit(':', 1)
                remote_port = int(remote_port_str)
            except ValueError:
                self.logger.log(f"Error unpacking IP and port from line: {line}")
                # Adding tuple (local_ip, local_port, remote_ip, remote_port) to connections list
            connections.append((local_ip, local_port, remote_ip, remote_port))
            cursor.execute('''
                            INSERT INTO CurrentConnections (local_ip, local_port, remote_ip, remote_port)
                            VALUES (?, ?, ?, ?)
            ''', (local_ip, local_port, remote_ip, remote_port))
            conn.commit()
                
        return connections
    
    def add_initial_trusted_connections(self):
        try:
            with sqlite3.connect(self.database_path) as conn:
                cursor = conn.cursor()
            cursor.execute("INSERT INTO TrustedConnections (IP_Address) VALUES ('127.0.0.1')")
            
            conn.commit()
            
        except sqlite3.Error as e:
            self.logger.log(f"Error adding initial trusted connection: {str(e)}")
          
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
        
    def baseline_scan(self):
        start_directory = "C:\\"
        self.Baseline_Scan(start_directory)
        
    def scheduled_file_scan(self):
        self.baseline_scan()
        self.s.enter(7200, 1, self.scheduled_file_scan, ())
        
    def scheduled_scan(self):
        self.connection_handler()
        self.Continuous_Scan()
        self.s.enter(900, 1, self.scheduled_scan, ())
        
    def run_scans(self):
        self.add_initial_trusted_connections()
        self.baseline_scan()
        self.connection_handler()
        self.Continuous_Scan()
        self.scheduled_scan()
        self.scheduled_file_scan()
        self.s.enter(7200, 1, self.scheduled_file_scan, ()) # Schedule the file scan to happen every 2 hours
        self.s.enter(900, 1, self.scheduled_scan, ())
        self.s.run()



if __name__ == "__main__":
    scanner = Scanner("GuardianAngel.db")
    scanner.run_scans()
    
    Menu.run()