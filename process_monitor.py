import psutil

def get_processes():
    """
    Returns a list of dictionaries containing
    information about running processes.
    """
    process_list = []

    for process in psutil.process_iter(['pid', 'ppid', 'name', 'exe']):
        try:
            process_info = {
                "name": process.info['name'],
                "pid": process.info['pid'],
                "ppid": process.info['ppid'],
                "path": process.info['exe']
            }

            process_list.append(process_info)

        except (psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess):
            pass

    return process_list


# Test this file directly
if __name__ == "__main__":

    processes = get_processes()

    for p in processes:

        print("=" * 60)
        print(f"Process Name : {p['name']}")
        print(f"PID          : {p['pid']}")
        print(f"PPID         : {p['ppid']}")
        print(f"Path         : {p['path']}")