from monitor import check_services

# Simulated service imformation
fake_services = [
    {
        "Name": "TestNewService",
        "PathName": "C:\\Windows\\System32\\test.exe"
    },
    {
        "Name": "TestNewService2",
        "PathName": "C:\\Windows\\System32\\test2.exe"
    }
]

# Use a separate testing baseline
alerts = check_services(
    fake_services,
    baseline_file="test_baseline.json"
)

print("\nDetection test results:")

if alerts:
    for alert in alerts:
        print(alert)
else: 
    print("No new services detected.")
