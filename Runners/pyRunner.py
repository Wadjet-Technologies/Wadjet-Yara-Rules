import os, yara 

rules = yara.compile(filepaths={'URLs': 'Rules/urls.yar'
                                ,'Files': 'Rules/files.yar'}
                    , externals={'filename': ''})

TARGET_FOLDER = r"C:\\Program Files"
print(f"Scanning folder: {TARGET_FOLDER}\n")
for root, dirs, files in os.walk(TARGET_FOLDER):
        for file in files:
            file_path = os.path.join(root, file)
            
            try:
                # 4. Scan the individual file
                matches = rules.match(file_path, externals={'filename': file})
                
                # 5. If a match is found, report it
                if matches:
                    print(f"[ALERT] Match found in: {file_path}")
                    print(f"        Rules triggered: {matches}\n")
                    
            except yara.Error:
                # Skips files that can't be processed (e.g., zero bytes or corrupted)
                continue
            except PermissionError:
                # Skips protected system files or directories without read access
                print(f"[!] Permission denied: {file_path}")
                continue

print("Scanning completed.")
