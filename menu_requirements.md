# Menu Requirements 
## Description:
Below are the requirements for the UI of MC-Hammer. Additional features may and will be added at a later date. The following is a list of the minimum requirements. 
## Requirements
### A persistant command line UI that runs until the exit function or keyboard interrupt occurs
### Fully functional selector switches
- This can include numbers or statements or an entire framework similar to metasploit
- A help feature with a list of commands, switches and descriptions
- The ability to view the following tables and query them for specific values, top values, unique values, head function, tail function, and the ability to execute SQL queries {if possible} (table names may change)
  1. Trusted connections 
  2. Current connections 
  3. Baseline executables 
  4. Registry Autoruns 
  5. Baseline accounts 
  6. Alerts 
- The alerts switch should have a counter beside it that shows the number of rows in the Alerts table until the alerts table is viewed then the counter restarts 
- A switch to start the scan must be included 
- A switch to exit the program should be included 
- A switch to add data to the databases with interactive, descriptive prompts and error handling should be included 
  - Priority goes to the TrustedConnections table 
- User prompt for input
### Additional features/nice-to-haves 
- A CLI like feel with the username of the user or the user that executed the program incorporated in the prompt 
- A timer that shows the start time and time-lapse of the current scans by scan types
- A timer that shows the time until the next scan by scan type