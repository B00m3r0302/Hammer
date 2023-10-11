## main.py
import time
import sqlite3
import concurrent.futures
import sys 
import sched
from menu import Menu
from scanner import Scanner
from actions import Actions
from logger import Logger

class Main:
    def __init__(self):
        self.menu = Menu()
        self.database_path = "GuardianAngel.db"
        self.s = sched.scheduler(time.time, time.sleep)
        self.scanner = Scanner(self.database_path)
        self.actions = Actions()
        self.logger = Logger()
    
    def connection_handler(self):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
        trusted_IP = self.actions.fetch_trusted_IPs(self.database_path)
        current_connections = self.scanner.get_current_connections()
        for ip in current_connections:
            if ip not in trusted_IP:
                self.logger.log(f"Blocking IP {ip}")
                self.actions.block_IP(ip)
                      
    def baseline_scan(self):
        start_directory = "C:\\"
        self.scanner.Baseline_Scan(start_directory)
        
    def scheduled_file_scan(self):
        self.baseline_scan()
        self.s.enter(7200, 1, self.scheduled_file_scan, ())
        
    def scheduled_scan(self):
        self.connection_handler()
        self.scanner.Continuous_Scan()
        self.s.enter(900, 1, self.scheduled_scan, ())
        
## TODO: Change code to use the UI that mark is going to build 
## TODO: Build the UI
## TODO: Add behavioral analytics from SnapAttack 
## TODO: Add actions to actions.py based on detections from SnapAttack analytics 
## TODO: Find a way to include an AI agent, LLM, or ML into the program with deep learning and a neural network.  If not possible at this time then we should focus on ML and training the model against current detections with the automated responses. 
## TODO: Create an 'Alerts' table that combines all of the information from the other discrepancies tables into a single table for ease of use and viewing.

    def run(self):
        try:
            self.menu.run()
            
            # Run baseline scan
            self.baseline_scan()
            self.connection_handler()
            self.scanner.Continuous_Scan()
            
            # Continuous scanning
            self.scheduled_scan()
            self.scheduled_file_scan()
            
            # scheduling
            self.s.enter(7200, 1, self.scheduled_file_scan, ()) # Schedule the file scan to happen every 2 hours
            self.s.enter(900, 1, self.scheduled_scan, ())
            self.s.run()
            
        except Exception as e:
            self.logger.log(f"An error occurred during scheduled scan: {str(e)}")

if __name__ == "__main__":
    main = Main()
    main.run()