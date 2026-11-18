<<<<<<< HEAD
# Windows service & Process Monitoring Agent

## 1. Project Overview 

This project implements a Windows Service and Processs Monitoring Agent using Python. 

The agent monitors Windows processes and services to identify potentially suspicious activity and generate security reports. 

It analyzes process relationships, executable locations, and Windows service configurations.

## 2. Technologies Used

- Python 
- Visual Studio Code 
- Windows 11
- psutil
- WMI
- PowerShell
- JSON
- CSV

## 3. Project Features 

1. Process monitoring using PID and PPID.
2. Suspicious parent-child process detection.
3. Detection of processes running from temporary folders. 
4. Windows service monitoring.
5. Detection of newly observed services. 
6. Service baseline creation and comparison.
7. Security alert generation.
8. CSV security report generation. 

## 4. Project Structure

'''text
WinMonitorAgent/
|
|-- venv/
|
|-- monitor.py
|-- test_detection.py
|-- test_parent_child.py
|-- test_temp.py
|
|-- requirements.txt
|-- README.md
|
|-- baseline_services.json
|-- report.csv
|
|-- test_baseline.json
|-- test_report.csv
'''

## 5. Installation

### Step 1: Create a virtual environment

'''powershell
python -m venv venv
'''

### Step 2: Activate the virtual environment

'''powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activatie.ps1
'''
### Step 3: Install dependecies

'''powershell
python -m pip install -r requirements.txt
'''

## 6. Execution

Run the monitoring agent:

'''powershell
python monitor.py
'''

## 7. Testing

The project includes separate testing scripts.

### Test new service detection

'''powershell
python test_detection.py
'''

### Test suspicious parent-child processes.

'''powershell
python test_parent_child.py
'''

### Test temporary-folder detection

'''powershell
python test_temp.py
'''

These tests use simulated data to verify detection logic without installing suspicious programs or modifying actual Windows services.

## 8. Generated Output Files

### baseline_services.json

Stores the names of Windows services observed during the initial baseline creation. 

### report.csv

Stores security alerts, including:

- Timestamp
- Severity
- Alert type
- Process or service details
- PID
- Executable path

## 9. Security Detection Examples

### Suspicious parent-child relationship

Example:

'''text
WINWORD.EXE
    |
    |_ POWERSHELL.EXE
'''

### Temporary-folder execution

Example:

'''text
C:\Users\Student\AppData\Local\Temp\unknown.exe
'''

### New Windows service

The monitoring agent compares currently observed service names against the saved baseline.

These detections are security indicators and do not independently prove malicious activity. 

## 10. Conclusion

The Windows service & Process Monitoring Agent demonstrates basic endpoint monitoring and suspicious process and service detection using Python on Windows.

The project collects process and service information, applies security detection rules, and generates CSV reports for further investigation. 

=======
# WinMonitorAgent
Windows Service and Process Monitoring Agent using Python for suspicious process and service detection.
>>>>>>> 0cb8ec104a1a668a049eff795eb286ad1b2ec896
