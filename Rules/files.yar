rule {
    meta:
        description = "A PowerShell file (Taskgmr.ps1) that Huntress believes to be an AI-assisted script conceals mining activity by stopping the service when Task Manager opens and restarting it when Task Manager closes."
    condition:
        yara.filename == "Taskgmr.ps1"
}