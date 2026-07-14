# detector.py

# ----------------------------------------
# Suspicious Parent -> Child Relationships
# ----------------------------------------
TEST_MODE = False
SUSPICIOUS_PARENTS = {

    "winword.exe": [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe"
    ],

    "excel.exe": [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe"
    ],

    "outlook.exe": [
        "powershell.exe",
        "cmd.exe"
    ]
}

# ----------------------------------------
# Blacklisted Processes
# ----------------------------------------

BLACKLIST = {
    "mimikatz.exe",
    "psexec.exe",
    "nc.exe",
    "netcat.exe",
    "procdump.exe"
}

# ----------------------------------------
# Process Name Spoofing
# ----------------------------------------

SPOOFED_NAMES = {
    "svch0st.exe",
    "expl0rer.exe",
    "1sass.exe",
    "winl0gon.exe",
    "csrsss.exe"
}


def detect_processes(processes):
    
    alerts = []

    # Build PID -> Process Name lookup
    pid_lookup = {}

    for process in processes:
        pid_lookup[process["pid"]] = (process["name"] or "").lower()

    # Analyze every process
    for process in processes:

        process_name = (process["name"] or "").lower()
        if not process_name:
            continue
        # --------------------------------
        # Test Mode
        # --------------------------------

        if TEST_MODE and process_name == "notepad.exe":

           alerts.append({
               "type": "PROCESS",
                "severity": "HIGH",
                "process": process["name"],
                "pid": process["pid"],
                "path": process["path"],
                "reason": "TEST MODE: Simulated malicious process"
            })
        process_path = (process["path"] or "").lower()
        parent_name = pid_lookup.get(process["ppid"], "")

        # Prevent duplicate alerts for the same process/rule
        detected = set()

        # --------------------------------
        # Rule 1
        # Executable running from suspicious folders
        # --------------------------------
        SYSTEM_PROCESSES = {
                "system",
                "registry",
                "memory compression",
                "idle"
            }
        if process_name in SYSTEM_PROCESSES:
            continue
        
        # --------------------------------

        # Rule
        # Missing Executable
        # --------------------------------

        if process["path"] == "":

            alerts.append({
                "type": "PROCESS",
                "severity": "MEDIUM",
                "process": process["name"],
                "pid": process["pid"],
                "path": "",
                "reason": "Executable path unavailable"
            })

        if (
            "\\temp\\" in process_path
            or "\\downloads\\" in process_path
            or "\\desktop\\" in process_path
        ):

            alerts.append({
                "type": "PROCESS",
                "severity": "HIGH",
                "process": process["name"],
                "pid": process["pid"],
                "path": process["path"],
                "reason": "Process running from suspicious folder"
            })

            detected.add("folder")

        # --------------------------------
        # Rule 2
        # Process Name Spoofing
        # --------------------------------

        if process_name in SPOOFED_NAMES and "spoof" not in detected:

            alerts.append({
                "type": "PROCESS",
                "severity": "MEDIUM",
                "process": process["name"],
                "pid": process["pid"],
                "path": process["path"],
                "reason": "Possible process name spoofing"
            })

            detected.add("spoof")



        # --------------------------------
        # Rule 3
        # Blacklisted Process
        # --------------------------------

        if process_name in BLACKLIST and "blacklist" not in detected:

            alerts.append({
                "type": "PROCESS",
                "severity": "HIGH",
                "process": process["name"],
                "pid": process["pid"],
                "path": process["path"],
                "reason": "Blacklisted process detected"
            })

            detected.add("blacklist")

        # --------------------------------
        # Rule 4
        # Suspicious Parent -> Child
        # --------------------------------

        if parent_name in SUSPICIOUS_PARENTS:

            if process_name in SUSPICIOUS_PARENTS[parent_name]:

                alerts.append({
                    "type": "PROCESS",
                    "severity": "HIGH",
                    "process": process["name"],
                    "pid": process["pid"],
                    "path": process["path"],
                    "reason": f"Suspicious parent-child relationship: {parent_name} -> {process_name}"
                })


    return alerts