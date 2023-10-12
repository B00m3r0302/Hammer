## main.py
import time
import sqlite3
import sys
import sched
from concurrent.futures import ThreadPoolExecutor
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
    
        
## TODO: Change code to use the UI that mark is going to build 
## TODO: Build the UI
## TODO: Add behavioral analytics from SnapAttack 
## TODO: Add actions to actions.py based on detections from SnapAttack analytics 
## TODO: Find a way to include an AI agent, LLM, or ML into the program with deep learning and a neural network.  If not possible at this time then we should focus on ML and training the model against current detections with the automated responses. 
## TODO: Create an 'Alerts' table that combines all of the information from the other discrepancies tables into a single table for ease of use and viewing.
## TODO: Add threading module to run the entire try block of run concurrently

    def run(self):
        try:
            self.menu.run()
            
        except Exception as e:
            self.logger.log(f"An error occurred during scheduled scan: {str(e)}")

if __name__ == "__main__":
    main = Main()
    main.run()