import wmi

def get_services():

    c = wmi.WMI()

    service_list = []

    for service in c.Win32_Service():

        service_info = {
            "name": service.Name,
            "state": service.State,
            "start_type": service.StartMode,
            "path": service.PathName
        }

        service_list.append(service_info)


    # Broader "user-writable" locations (rule 4) - not inherently malicious,
    # but unusual for a legitimate service to run from here
    USER_WRITABLE_DIRS = [
        r"\users\\",
        r"\appdata\\",
    ]
    return service_list
def _normalize_path(path):
    if not path:
        return None
    return path.strip().strip('"').lower().replace("/", "\\")

def _in_any(path, dir_list):
    return any(d in path for d in dir_list)

def detect_suspicious_services(services):
    import os
    import re
    import wmi

    # Locations commonly abused for persistence / staging malicious binaries
    SUSPICIOUS_DIRS = [
        r"\temp\\",
        r"\tmp\\",
        r"\downloads\\",
        r"\desktop\\",
        r"\appdata\local\temp",
        r"\programdata\\",  # sometimes flagged separately, remove if too noisy
    ]

    # Broader "user-writable" locations (rule 4) - not inherently malicious,
    # but unusual for a legitimate service to run from here
    USER_WRITABLE_DIRS = [
        r"\users\\",
        r"\appdata\\",
    ]

    alerts = []

    for svc in services:
        name = svc.get("name", "Unknown")
        state = svc.get("state", "Unknown")
        start_type = (svc.get("start_type") or "").strip().lower()
        raw_path = svc.get("path")

        norm_path = _normalize_path(raw_path)

        # Rule 3: missing executable path
        if norm_path is None:
            
            continue

        in_temp_like = _in_any(norm_path, SUSPICIOUS_DIRS)
        in_user_writable = _in_any(norm_path, USER_WRITABLE_DIRS)

        # Rule 1: executable in Temp/Downloads/Desktop
        if in_temp_like:
            alerts.append({
                "type": "SERVICE",
                "service": name,
                "severity": "HIGH",
                "reason": "Service executable is located in Temp/Downloads/Desktop.",
                "state": state,
                "start_type": start_type,
                "path": raw_path,
            })

        # Rule 2: Automatic startup + suspicious location
        if start_type == "automatic" and in_temp_like:
            alerts.append({
                "type": "SERVICE",
                "service": name,
                "severity": "HIGH",
                "reason": "Service is set to start automatically from a suspicious location (potential persistence).",
                "state": state,
                "start_type": start_type,
                "path": raw_path,
            })

        # Rule 4: user-writable location (broader, lower confidence than Rule 1)
        if in_user_writable and not in_temp_like:
            alerts.append({
                "type": "SERVICE",
                "service": name,
                "severity": "MEDIUM",
                "reason": "Service executable runs from a user-writable location.",
                "state": state,
                "start_type": start_type,
                "path": raw_path,
            })

    return alerts
if __name__ == "__main__":

    services = get_services()

    for service in services:

        print("=" * 60)
        print(f"Service Name : {service['name']}")
        print(f"State        : {service['state']}")
        print(f"Startup Type : {service['start_type']}")
        print(f"Path         : {service['path']}")