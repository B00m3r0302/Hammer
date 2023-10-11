import subprocess
from logger import Logger
import sqlite3
import os
import winreg


class Actions:
    def __init__(self):
        self.database_path = "GuardianAngel.db"
        self.logger = Logger()

    def fetch_trusted_IPs(self):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
        cursor.execute("SELECT IP_Address FROM TrustedConnections")
        trusted_ips = [row[0] for row in cursor.fetchall()]
        conn.close()
        return trusted_ips

    def block_IP(self, ip):
        try:
            subprocess.check_call(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in interface=any action=block remoteip={ip}", shell=True)
        except subprocess.CalledProcessError as e:
            self.logger.log(f"Error blocking IP {ip}: {e}")
    
    def remove_executable(self, file_path):
        os.remove(file_path)
        
    def delete_registry_autorun(self, hive, subkey, name):
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
                self.logger.log(f"Deleted registry autorun entry {name}")
        except WindowsError as e:
            self.logger.log(f"Error deleting registry autorun entry {name} with error: {str(e)}")
            
    def remove_users(self, username):
        try:
            # Using 'net user' command to delete the Guest account
            os.system(f"net user {username} /active:no")
            self.logger.log(f"User '{username}' has been disabled")
        except Exception as e:
            self.logger.log(f"Error deleting user '{username}' with error: {str(e)}")
