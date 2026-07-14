from datetime import datetime


def save_alerts(alerts):

    with open("logs/alerts.log", "a", encoding="utf-8") as file:

        for alert in alerts:

            file.write("=" * 60 + "\n")
            file.write(f"Time      : {datetime.now()}\n")
            file.write(f"Type      : {alert['type']}\n")
            file.write(f"Severity  : {alert['severity']}\n")

            # -------------------------
            # Process Alert
            # -------------------------
            if alert["type"] == "PROCESS":

                file.write(f"Process   : {alert['process']}\n")
                file.write(f"PID       : {alert['pid']}\n")

            # -------------------------
            # Service Alert
            # -------------------------
            elif alert["type"] == "SERVICE":

                file.write(f"Service   : {alert['service']}\n")
                file.write(f"State     : {alert['state']}\n")
                file.write(f"Startup   : {alert['start_type']}\n")

            file.write(f"Path      : {alert['path']}\n")
            file.write(f"Reason    : {alert['reason']}\n")
            file.write("=" * 60 + "\n\n")

    print(f"{len(alerts)} alert(s) saved.")