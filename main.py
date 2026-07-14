import time

from process_monitor import get_processes
from service_monitor import get_services, detect_suspicious_services

from detector import detect_processes
from logger import save_alerts


print("Windows Monitoring Agent Started...")

while True:

    print("\nScanning system...")

    processes = get_processes()

    services = get_services()

    process_alerts = detect_processes(processes)

    service_alerts = detect_suspicious_services(services)

    alerts = process_alerts + service_alerts

    if alerts:

        print(f"{len(alerts)} alert(s) detected.")

        for alert in alerts:
            
            print("=" * 50)
            print(f"Type     : {alert['type']}")
            print(f"Severity : {alert['severity']}")

            if alert["type"] == "PROCESS":
                print(f"Process  : {alert['process']}")
                print(f"PID      : {alert['pid']}")
    
            elif alert["type"] == "SERVICE":
                print(f"Service  : {alert['service']}")
                print(f"State    : {alert['state']}")
                print(f"Startup  : {alert['start_type']}")

            print(f"Path     : {alert['path']}")
            print(f"Reason   : {alert['reason']}")

        save_alerts(alerts)

    else:

        print("No suspicious activity detected.")

    print(f"Processes scanned : {len(processes)}")
    print(f"Services scanned  : {len(services)}")

    print("-" * 60)

    time.sleep(5)