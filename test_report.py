from monitor import write_report

# Create a simulated security alert
test_alerts = [
    { 
        "severity": "HIGH",
        "type": "Test alert",
        "detail": "Simulated test process",
        "pid": 1234,
        "path": "C:\\Test\\test.exe"
    }
]

# Generate a separate test CSV report
write_report(
    test_alerts,
    "test_report.csv"
)

print("CSV report test completed successfully!")
