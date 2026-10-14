import os, yara, traceback, psutil, json 

def load_yara():
    rules= yara.compile(filepaths={'URLs': 'Rules/urls.yar'
                                    ,'Files': 'Rules/files.yar'
                                    ,'Memory': 'Rules/memory.yar'}
                        , externals={'filename': ''})

    exclusions = json.load(open('Runners/Exclusions.json', 'r'))
    return rules, exclusions

def scan_folder(rules, exclusions, TARGET_FOLDER = r"C:\\"):
    for root, dirs, files in os.walk(TARGET_FOLDER):
        if any(excluded_path in root for excluded_path in exclusions.get("Path Exclusions", [])):
            print(f"[🔄] Skipping Parent excluded path: {root}")
            continue
        for file in files:
            file_path = os.path.join(root, file)
            if any(excluded_path in file_path for excluded_path in exclusions.get("Path Exclusions", [])):
                        print(f"[🔄] Skipping excluded file: {file_path}")
                        continue
            try:
                # 4. Scan the individual file
                matches = rules.match(file_path, externals={'filename': file})
                
                # 5. If a match is found, report it
                if matches:
                    print(f"[🚨ALERT] Match found in: {file_path}")
                    for m in matches:
                        print(f"    - Rule: {m.rule} (Namespace: {m.namespace})")
                        print(f"            ON: {m.strings}\n")

            except yara.Error as e:
                # Skips files that can't be processed (e.g., zero bytes or corrupted)
                print(f"[!] Error processing file: {file_path}")
                print(f"    Error: {e}", root)
                continue
            except PermissionError:
                # Skips protected system files or directories without read access
                print(f"[!] Permission denied: {file_path}")
                continue


def scan_memory(rules, exclusions):
    for proc in psutil.process_iter(["pid", "name", 'exe']):
        try:
            name = proc.info['name']
            pid = proc.info['pid']
            exe = proc.info['exe']

            matches = rules.match(pid=pid)
            if matches:
                print(f"[+] Match in {name} (PID: {pid} | Executable: {exe}):")
                for m in matches:
                    print(f"    - {m.rule} (Namespace: {m.namespace}) \n {m}")
        except (psutil.AccessDenied, psutil.NoSuchProcess, yara.Error) as e:
            # Skip processes protected by the OS or that exit during scanning
            print(f"[!] Could not scan process: {name} (PID: {pid} | Executable: {exe})")
            print("    Error:", e)
            continue
  
  


if __name__ == "__main__":
    print("Loading YARA rules and exclusions...\n")
    rules, exclusions = load_yara()

    print("Starting folder scan...\n")
    scan_folder(rules, exclusions)

    print("Folder scan complete. Scanning Memory...\n")
    scan_memory(rules, exclusions)
    print("Memory scan complete.")
    print("Scanning complete. Exiting.")