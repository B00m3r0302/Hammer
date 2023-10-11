import sqlite3
import subprocess

class Highest_Highest:
    def __init__(self, database_path):
        self.database_path = database_path
        
    def setup_database(self):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                           CREATE TABLE IF NOT EXISTS Highest_Sev_Highest_Conf (
                               id INTEGER PRIMARY KEY,
                               TimeCreated TEXT,
                               RecordId TEXT,
                               ProcessId TEXT,
                               MachineName TEXT,
                               Message TEXT
                            )
                            ''')
            conn.commit()
            conn.close()
            
    def LSASS_Access_From_Non_System_Account(self):
        with sqlite3.connect(self.database_path) as conn:
            cursor = conn.cursor()
        
        cmd = [
            'powershell',
            'Get-WinEvent | where {((($_.ID -eq "4663" -or $_.ID -eq "4656") -and ($_.message -match "AccessMask.*0x40" -or $_.message -match "AccessMask.*0x1400" -or $_.message -match "AccessMask.*0x100000" -or $_.message -match "AccessMask.*0x1410" -or $_.message -match "AccessMask.*0x1010" -or $_.message -match "AccessMask.*0x1438" -or $_.message -match "AccessMask.*0x143a" -or $_.message -match "AccessMask.*0x1418" -or $_.message -match "AccessMask.*0x1f0fff" -or $_.message -match "AccessMask.*0x1f1fff" -or $_.message -match "AccessMask.*0x1f2fff" -or $_.message -match "AccessMask.*0x1f3fff" -or $_.message -match "AccessMask.*40" -or $_.message -match "AccessMask.*1400" -or $_.message -match "AccessMask.*1000" -or $_.message -match "AccessMask.*100000" -or $_.message -match "AccessMask.*1410" -or $_.message -match "AccessMask.*1010" -or $_.message -match "AccessMask.*1438" -or $_.message -match "AccessMask.*143a" -or $_.message -match "AccessMask.*1418" -or $_.message -match "AccessMask.*1f0fff" -or $_.message -match "AccessMask.*1f1fff" -or $_.message -match "AccessMask.*1f2fff" -or $_.message -match "AccessMask.*1f3fff") -and $_.message -match "ObjectType.*Process" -and $_.message -match "ObjectName.*.*\\lsass.exe") -and  -not ($_.message -match "SubjectUserName.*.*$" -or $_.message -match "ProcessName.*C:\\Program Files.*" -or ($_.message -match "ProcessName.*C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" -and $_.message -match "AccessMask.*0x1410") -or $_.message -match "ProcessName.*.*\\SteamLibrary\\steamapps\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Parse the output
        events = eval(result.stdout) # Convert the output JSON string to a python list
            
        # Save to the database
        for event in events:
            cursor.execute('''
                           INSERT INTO Highest_Sev_Highest_Conf (TimeCreated, RecordId, ProcessId, MachineName, Message)
                           VALUES (?, ?, ?, ?, ?)
                           ''', (event['TimeCreated'], event['RecordId'], event['ProcessId'], event['MachineName'], event['Message']))
            conn.commit()
            conn.close()

if __name__ == "__main__":
    Highest_Highest = Highest_Highest()
    Highest_Highest.setup_database()
    Highest_Highest.LSASS_Access_From_Non_System_Account()
    
        
        


