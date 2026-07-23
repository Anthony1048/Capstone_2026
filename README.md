Project Overview


This project is a portable Windows security scanner designed to run directly from a USB drive. It
requires no installation and no Python on the user’s machine. The application uses:

▪ C++ for the UI, JSON parsing, and HTML report generation
▪ Python for executing system checks
▪ PowerShell for querying Windows security settings
▪ HTML/CSS for the final report

The program launches a local web server, performs security scans, and generates a styled HTML
report.

Features

▪ Firewall status detection
▪ RDP configuration check
▪ UAC status check
▪ BitLocker drive protection check
▪ SMBv1 detection
▪ Remote access status
▪ Windows Defender status
▪ Local administrator detection
▪ System specifications (CPU, RAM, GPU)
▪ Full JSON contract output
▪ HTML report generation
▪ Runs without Python installed

USB Folder Structure
.
├── Capstone.exe
├── generated reports
│   ├── final_report.html
│   └── report.json
├── html
│   ├── Capstone.html
│   ├── index.html
│   └── style.css
├── powershell
│   ├── bitlocker_status.ps1
│   ├── defender_status.ps1
│   ├── local_admins.ps1
│   ├── query_firewall.ps1
│   ├── query_smvb.ps1
│   ├── rdp_config.ps1
│   ├── rremote_enabled.ps1
│   ├── uac_status_check.ps1
│   └── Week6
│       ├── defender_status.ps1
│       ├── local_admins.ps1
│       └── rremote_enabled.ps1
└── python
    ├── report_generator.exe
    └── scanner.exe



Build Instructions (Developer Only)
1. Install CMake and Visual Studio Build Tools
2. Configure CMake in Release mode
3. Build the executable
4. Copy Capstone.exe to the USB
5. Add Python embeddable package
6. Add PowerShell scripts
7. Add web UI files



Run Instructions (User)
1. Plug in the USB drive
2. Folder should open automatically, open folder if it doesn't 
3. Run Capstone.exe

Contributors

▪ Team Lead - Anthony Corbin
▪ C++ Developer - Daniel Gilbody 
▪ Python Developer - Patrick Guindy 
▪ PowerShell Developer - Umme Ayesha
▪ HTML Developer - Susani Tamang 
▪ Testing and Documentation - Jacob Green

