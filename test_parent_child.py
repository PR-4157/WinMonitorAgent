from monitor import check_parent_child

# Simulated process information
fake_processes = {

    100: {
        "pid": 100,
        "ppid": 1,
        "name": "winword.exe",
        "exe": "c:\\Program Files\\Microsoft Office\\winword.exe"
    },

    200: {
        "pid": 200,
        "ppid": 100,
        "name": "powershell.exe",
        "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    }

}

#Run the detection function
alerts = check_parent_child(fake_processes)

print("\nParent-child detection results:")

if alerts:
    for alert in alerts:
        print(alert)

else: 
    print("No suspicious relationship detected.")

