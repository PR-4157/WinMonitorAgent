from monitor import check_unauthorized

# Simulated process running from Temp
fake_processes = {

    500: {
        "pid": 500,
        "ppid": 1,
        "name": "unknown.exe",
        "exe": "C:\\Users\\Rahulkumar\\AppData\\Local\\Temp\\unknown.exe"
    }
}

# Run detection
alerts = check_unauthorized(fake_processes)

print("\nTemporary-folder detection results:")

if alerts:
    for alert in alerts:
        print(alert)

else:
    print("No suspicious process locations detected.")