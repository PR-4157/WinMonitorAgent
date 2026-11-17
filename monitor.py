import psutil
import json
import platform
import subprocess
import csv
import os

from datetime import datetime

def get_processes():
    """
    Collects information about currently running processes."""

    processes = {}

    for process in psutil.process_iter(
        ["pid", "ppid", "name", "exe"]
    ):
        
        try: 
            info = process.info

            pid = info["pid"]

            processes[pid] = info 

        except (
            psutil.NoSuchProcess, 
            psutil.AccessDenied
        ):
            continue

    return processes

SUSPICIOUS_PAIRS = {
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe")
}

def check_parent_child(processes): 

    alerts = []

    for pid, info in processes.items(): 

        parent = processes.get(info["ppid"])

        if parent is None: 
            continue

        if not info["name"] or not parent["name"]: 
            continue

        pair = (
            parent["name"].lower(), 
            info["name"].lower()
        )

        if pair in SUSPICIOUS_PAIRS:

            alerts.append({
                "Severity": "HIGH", 
                "type": "Suspicious parent-child",
                "details": (
                    parent["name"] + " launched " + info["name"]
                ),
                "pid": pid, 
                "path": info["exe"] or ""
            })

    return alerts

TEMP_MARKERS = [
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\downloads\\"
]

def check_unauthorized(processes):

    alerts = []

    for pid, info in processes.items():

        path = (info["exe"] or "").lower()

        if any(marker in path for marker in TEMP_MARKERS):

            alerts.append({
                "severity": "MEDIUM",
                "type": "Process from temp folder",
                "detail": info["name"] or "unknown",
                "pid": pid,
                "path": info["exe"] or ""
            })

    return alerts

def get_services():

    if platform.system() != "Windows":
        print("Service audit skipped: Windows only")
        return []

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_Service |",
        "Select-Object Name, DisplayName, PathName, StartMode, State |",
        "ConvertTo-Json -Depth 3"
    ]

    try: 
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            print("PowerShell service collection failed:")
            print(result.stderr)
            return []
        
        if not result.stdout.strip():
            print("Np service information received.")
            return []
        
        services = json.loads(result.stdout)

        if isinstance(services, dict):
            services = [services]

        if not isinstance(services, list):
            print("Unexpected service data format.")
            return []

        return services

    except subprocess.TimeoutExpired: 
        print("Service collection timed out.")
        return []

    except json.JSONDecodeError:
        print("Could not read service information.")
        return []

    except Exception as error: 
        print("Service collection error:", error)
        return []

def check_services(
        services,
        baseline_file="baseline_services.json"
):

    alerts = []

    # Initialize the variable before reading the file
    known = None

    # Do not create a baseline from an empty collection
    if not services: 
        print("No service data available. Baseline not changed.")
        return alerts

    # Collect current service names
    current_names = {
        service.get("Name")
        for service in services
        if service.get("Name")
    }

    # Check services executable locations
    for service in services: 

        path = (
            service.get("PathName") or ""
        ).lower()

        if any(
            marker in path
            for marker in TEMP_MARKERS
        ):

            alerts.append({
                "serverity": "HIGH",
                "type": "Service from suspicious folder",
                "detail": service.get("Name", "Unknown"),
                "pid": "",
                "path": service.get("PathName", "")
            })

    # Read existing baseline
    try: 

        with open(
            baseline_file,
            "r",
            encoding="utf-8"
        ) as file:

            known = json.load(file)

        if not isinstance(known, list):
            print("Invalid baseline format. Please review the JSON file.")
            return alerts

        known = set(known)

    except FileNotFoundError:

        known = None

    except (json.JSONDecoderError, OSError) as error:

        print("Could not read service baseline:", error)
        return alerts 

    # First run: create the baseline
    if known is None:

        with open(
            baseline_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                sorted(current_names),
                file,
                indent=4
            )
        print("Service baseline created.")

    else: 

        # Detect services that were not in the baseline
        new_services = current_names - known

        for service_name in sorted(new_services):

            service = next(
                (
                    item for item in services
                    if item.get("Name") == service_name
                ),
                {}
            )

            alerts.append({
                "severity": "HIGH",
                "type": "New service detected",
                "detail": service_name,
                "pid": "",
                "path": service.get("PathName", "")
            })

    return alerts


def write_report(
        alerts,
        filename="report.csv"
):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    file_exists = os.path.exists(filename)

    with open(
        filename,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        # Write column headings only once
        if not file_exists or os.path.getsize(filename) == 0:

            writer.writerow([
                "timestamp",
                "serverity",
                "type",
                "detail",
                "pid",
                "path"
            ])

        # Write security alerts
        for alert in alerts: 

            writer.writerow([
                timestamp, 
                alert.get("severity", "UNKNOWN"),
                alert.get("type", "UNKNOWN"),
                alert.get("detail", ""),
                alert.get("pid", ""),
                alert.get("path", "")
            ])

    print("Security report saved:", filename)


if __name__ == "__main__":

    print("=" * 50)
    print("WINDOWS SERVICE & PROCESS MONITORING AGENT")
    print("=" * 50)

    # Step 1: Collect running processes
    print("\n[1] Collecting processes...")

    processes = get_processes()

    print("Processes found:", len(processes))

    # Step 2: Collect Windows services
    print("\n[2] Collecting Windows services...")

    services = get_services()

    print("Services found:", len(services))

    # Step 3: Detect suspicious activity
    print("\n[3] Checking security alerts...")

    alerts = []

    alerts += check_parent_child(processes)

    alerts += check_unauthorized(processes)

    alerts += check_services(services)

    # Step 4: Display alerts

    print("\n[4] Security alerts:")

    if alerts: 

        for alert in alerts: 

            print("\n------------------------")

            if isinstance(alert,dict):
                
                print("Severity:", alert.get("severity", "UNKNOWN"))
                
                print("Type:", alert.get("type", "UNKNOWN"))
                
                print("Detail:", alert.get("detail", "No details"))
                
                print("PID:", alert.get("pid", "N/A"))
                
                print("Path:", alert.get("path", "N/A"))

                # Show all fields for debugging
                if "severity" not in alert:
                    print("WARNING: Alert is missing severity!")
                    print("Full alert:", alert)

            else: 
                print("Invalid alert format:", repr(alert))

    else: 
        print("No suspicious activity detected.")

    # Step 5: Generate CSV report
    print("\n[5] Generating security report...")

    write_report(alerts)

    # Step 6: Finish
    print("\nMonitoring scan completed.")

    print("=" * 50)

    services = get_services()

    print("Services found:", len(services))

    for service in services[:10]:
        print(
            "Name:", service.get("Name"),
            "| State:", service.get("State"),
            "| Start Mode:", service.get("StartMode")
        )

    print("WINDOWS PROCESS MONITOR")
    print("-----------------------")

    print(f"Total processes: {len(processes)}")

    print("\nFirst 10 running processes:")

    for pid, info in list(processes.items())[:10]:

        print(
            "PID:", pid, 
            "| PPID:", info["ppid"],
            "| Name:", info["name"],
            "| Path:", info["exe"]
        )