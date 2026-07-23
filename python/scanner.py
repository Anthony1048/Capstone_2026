import sys
import subprocess
import json
import socket
import platform
from datetime import datetime, UTC
import os
import psutil

# When frozen as a PyInstaller exe, __file__ is unreliable
# Use sys.executable to get the actual exe directory instead
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# PowerShell scripts are located one level up from the python folder
POWERSHELL_DIR = os.path.join(BASE_DIR, "..", "powershell")

# Maps check names to their corresponding PowerShell script filenames
SCRIPTS = {
    "firewall": "query_firewall.ps1",
    "rdp": "rdp_config.ps1",
    "uac": "uac_status_check.ps1",
    "bitlocker": "bitlocker_status.ps1",
    "smb": "query_smvb.ps1",
    "rremote": "rremote_enabled.ps1",
    "defender": "defender_status.ps1",
    "local_admin": "local_admins.ps1"
}


def run_powershell_script(script_name):
    """Run a PowerShell script and return its parsed JSON output."""
    script_path = os.path.join(POWERSHELL_DIR, script_name)
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=20
        )

        # Strip BOM and whitespace from output
        stdout_clean = (result.stdout or "").replace("\ufeff", "").strip()
        stderr_clean = (result.stderr or "").strip()

        # Collect debug info for troubleshooting
        debug = {
            "script_path": script_path,
            "returncode": result.returncode,
            "stdout": stdout_clean,
            "stderr": stderr_clean,
        }

        # Return error if script produced no output
        if not stdout_clean:
            return {
                "data": None,
                "error": stderr_clean or "Empty PowerShell output",
                "ok": False,
                "debug": debug
            }

        # Parse the JSON output from the PowerShell script
        try:
            data = json.loads(stdout_clean)
        except json.JSONDecodeError as e:
            return {
                "data": None,
                "error": f"Malformed JSON from PowerShell: {e}",
                "ok": False,
                "debug": debug
            }

        if data is None:
            return {
                "data": None,
                "error": "No PowerShell output was returned.",
                "ok": False,
                "debug": debug
            }

        return {
            "data": data.get("data"),
            "error": data.get("error"),
            "ok": data.get("ok"),
            "check": data.get("check"),
            "debug": debug
        }

    except Exception as e:
        return {
            "data": None,
            "error": str(e),
            "ok": False,
            "debug": {"script_path": script_path}
        }


def get_gpu_info():
    """Query the GPU name via PowerShell WMI."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-WmiObject Win32_VideoController | Select-Object -First 1).Caption"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() or "N/A"
    except Exception:
        return "N/A"


def build_final_contract(results):
    """
    Process raw PowerShell results into a structured scan report.
    Returns a dict with findings, statuses, system info, and debug data.
    """
    findings = []
    statuses = []
    errors = []
    debug = {}

    # Collect hardware and OS info for the report header
    system_info = {
        "hostname": socket.gethostname(),
        "windows_version": platform.platform(),
        "cpu": f"{psutil.cpu_count(logical=False)} Cores ({platform.processor()})",
        "ram": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB",
        "disk": f"{round(psutil.disk_usage('C:').total / (1024**3), 2)} GB",
        "gpu": get_gpu_info()
    }

    for check_name, result in results.items():
        #print("CHECK NAME:", check_name, file=sys.stderr)

        error_msg = result.get("error")
        data = result.get("data")
        debug[check_name] = result.get("debug")

        # Log execution errors and mark the check as failed if no data returned
        if error_msg:
            errors.append({
                "check": check_name,
                "message": error_msg,
                "type": "execution_error"
            })
            if data is None:
                statuses.append({
                    "id": check_name.upper(),
                    "name": check_name.replace("_", " ").title(),
                    "status": "Error",
                    "description": f"Check could not be completed: {error_msg}"
                })
                continue

        # ---------- FIREWALL ----------
        if check_name == "firewall" and isinstance(data, list):
            disabled_profiles = [
                p["Name"] for p in data if not p.get("Enabled", True)
            ]
            if disabled_profiles:
                findings.append({
                    "id": "FW-001",
                    "name": "Firewall Disabled",
                    "severity": "Critical",
                    "description": "One or more Windows Firewall profiles are disabled.",
                    "evidence": f"Disabled profiles: {', '.join(disabled_profiles)}",
                    "remediation": "Enable all Windows Firewall profiles."
                })
                statuses.append({
                    "id": "FW",
                    "name": "Windows Firewall",
                    "status": "Fail",
                    "description": f"Disabled profiles: {', '.join(disabled_profiles)}"
                })
            else:
                enabled_profiles = [p["Name"] for p in data if p.get("Enabled", True)]
                statuses.append({
                    "id": "FW",
                    "name": "Windows Firewall",
                    "status": "Pass",
                    "description": f"All firewall profiles are enabled: {', '.join(enabled_profiles)}"
                })

        # ---------- RDP ----------
        elif check_name == "rdp" and isinstance(data, dict):
            if data.get("RDPEnabled", False):
                findings.append({
                    "id": "RDP-001",
                    "name": "Remote Desktop Enabled",
                    "severity": "Medium",
                    "description": "Remote Desktop is enabled.",
                    "evidence": f"RDPEnabled=True",
                    "remediation": "Disable RDP if not required."
                })
                statuses.append({
                    "id": "RDP",
                    "name": "Remote Desktop Protocol",
                    "status": "Fail",
                    "description": "RDP is enabled and may expose the system to remote access."
                })
            else:
                statuses.append({
                    "id": "RDP",
                    "name": "Remote Desktop Protocol",
                    "status": "Pass",
                    "description": "RDP is disabled."
                })

        # ---------- UAC ----------
        elif check_name == "uac" and isinstance(data, dict):
            # print("UAC RAW DATA:", data, file=sys.stderr)

            uac_enabled = data.get("UACEnabled")

            if uac_enabled is None:
                errors.append({
                    "check": "uac",
                    "message": "UAC value missing."
                })
                statuses.append({
                    "id": "UAC",
                    "name": "User Account Control",
                    "status": "Error",
                    "description": "UAC status could not be determined."
                })
                continue

            # Normalize to bool — PowerShell may return "True", "1", etc.
            is_enabled = str(uac_enabled).strip().lower() in ["true", "1"]

            if not is_enabled:
                findings.append({
                    "id": "UAC-001",
                    "name": "User Account Control Disabled",
                    "severity": "Medium",
                    "description": "UAC is disabled.",
                    "evidence": f"UACEnabled={uac_enabled}",
                    "remediation": "Enable UAC in Windows settings."
                })
                statuses.append({
                    "id": "UAC",
                    "name": "User Account Control",
                    "status": "Fail",
                    "description": "UAC is disabled, reducing protection against unauthorized changes."
                })
            else:
                statuses.append({
                    "id": "UAC",
                    "name": "User Account Control",
                    "status": "Pass",
                    "description": "UAC is enabled."
                })

        # ---------- BITLOCKER ----------
        elif check_name == "bitlocker" and isinstance(data, dict):
            if data.get("MountPoint") == "C:":
                # ProtectionStatus may be returned as "On", "1", or "True"
                protected = str(data.get("ProtectionStatus", "")).strip().lower() in ["on", "1", "true"]

                if not protected:
                    findings.append({
                        "id": "BL-001",
                        "name": "BitLocker Disabled",
                        "severity": "High",
                        "description": "BitLocker protection appears to be disabled on the system drive.",
                        "evidence": f"C: ProtectionStatus={data.get('ProtectionStatus')} VolumeStatus={data.get('VolumeStatus')}",
                        "remediation": "Enable BitLocker on the system drive."
                    })
                    statuses.append({
                        "id": "BL",
                        "name": "BitLocker Drive Encryption",
                        "status": "Fail",
                        "description": f"C: drive is not protected. ProtectionStatus={data.get('ProtectionStatus')}"
                    })
                else:
                    statuses.append({
                        "id": "BL",
                        "name": "BitLocker Drive Encryption",
                        "status": "Pass",
                        "description": "C: drive is BitLocker protected."
                    })
            else:
                errors.append({
                    "check": "bitlocker",
                    "message": "OS drive (C:) was not found in BitLocker output."
                })
                statuses.append({
                    "id": "BL",
                    "name": "BitLocker Drive Encryption",
                    "status": "Error",
                    "description": "C: drive status could not be determined."
                })

        # ---------- SMB ----------
        elif check_name == "smb" and isinstance(data, dict):
            if data.get("Enabled", False):
                findings.append({
                    "id": "SMB-001",
                    "name": "SMBv1 Enabled",
                    "severity": "High",
                    "description": "SMBv1 is enabled.",
                    "evidence": f"State={data.get('State')}",
                    "remediation": "Disable SMBv1."
                })
                statuses.append({
                    "id": "SMB",
                    "name": "SMBv1 Protocol",
                    "status": "Fail",
                    "description": "SMBv1 is enabled. This legacy protocol has known vulnerabilities."
                })
            else:
                statuses.append({
                    "id": "SMB",
                    "name": "SMBv1 Protocol",
                    "status": "Pass",
                    "description": "SMBv1 is disabled."
                })

        # ---------- REMOTE ----------
        elif check_name == "rremote" and isinstance(data, dict):
            if data.get("Enabled", False):
                findings.append({
                    "id": "R-001",
                    "name": "Remote Access Enabled",
                    "severity": "High",
                    "description": "Remote access is enabled.",
                    "evidence": f"Enabled=True",
                    "remediation": "Disable if not needed."
                })
                statuses.append({
                    "id": "RA",
                    "name": "Remote Access",
                    "status": "Fail",
                    "description": "Remote access is enabled on this system."
                })
            else:
                statuses.append({
                    "id": "RA",
                    "name": "Remote Access",
                    "status": "Pass",
                    "description": "Remote access is disabled."
                })

        # ---------- DEFENDER ----------
        elif check_name == "defender" and isinstance(data, dict):
            defender_enabled = data.get("DefenderEnabled")
            realtime = data.get("RealTimeProtection")

            if defender_enabled is False or realtime is False:
                findings.append({
                    "id": "DEF-001",
                    "name": "Windows Defender Protection Reduced",
                    "severity": "High",
                    "description": "Windows Defender or Real-Time Protection is disabled.",
                    "evidence": f"DefenderEnabled={defender_enabled}, RealTimeProtection={realtime}",
                    "remediation": "Enable Windows Defender and Real-Time Protection."
                })
                statuses.append({
                    "id": "DEF",
                    "name": "Windows Defender",
                    "status": "Fail",
                    "description": f"DefenderEnabled={defender_enabled}, RealTimeProtection={realtime}"
                })
            else:
                statuses.append({
                    "id": "DEF",
                    "name": "Windows Defender",
                    "status": "Pass",
                    "description": f"Defender is active with real-time protection enabled."
                })

        # ---------- LOCAL ADMIN ----------
        elif check_name == "local_admin" and isinstance(data, dict):
            is_current_user_admin = data.get("IsCurrentUserAdmin", False)
            built_in_admin_enabled = data.get("BuiltInAdministratorEnabled", False)
            admin_count = data.get("Count", 0)
            admins = data.get("Administrators", [])
            current_user = data.get("CurrentUser", "Unknown")

            la_findings_before = len(findings)

            # Flag if the current user has admin rights (principle of least privilege)
            if is_current_user_admin:
                findings.append({
                    "id": "LA-001",
                    "name": "Current User Has Administrator Privileges",
                    "severity": "High",
                    "description": "The current user is a member of the local Administrators group.",
                    "evidence": f"CurrentUser={current_user}, IsCurrentUserAdmin={is_current_user_admin}",
                    "remediation": "Use a standard user account for daily activity and reserve administrator privileges for administrative tasks only."
                })

            # Flag if the built-in Administrator account is active
            if built_in_admin_enabled:
                findings.append({
                    "id": "LA-002",
                    "name": "Built-in Administrator Account Present",
                    "severity": "Medium",
                    "description": "The built-in Administrator account is present in the local Administrators group.",
                    "evidence": f"BuiltInAdministratorPresent={built_in_admin_enabled}",
                    "remediation": "Ensure the built-in Administrator account is disabled or tightly controlled."
                })

            # Flag if more than one admin account exists
            if admin_count > 1:
                findings.append({
                    "id": "LA-003",
                    "name": "Multiple Administrator Accounts Present",
                    "severity": "Medium",
                    "description": "Multiple accounts have administrator privileges on this system.",
                    "evidence": f"AdministratorCount={admin_count}; Members={[a.get('Name') for a in admins]}",
                    "remediation": "Review administrative group membership and remove unnecessary privileged accounts."
                })

            if len(findings) > la_findings_before:
                statuses.append({
                    "id": "LA",
                    "name": "Local Administrator Accounts",
                    "status": "Fail",
                    "description": f"Administrator account issues detected. Admin count: {admin_count}, CurrentUserIsAdmin: {is_current_user_admin}"
                })
            else:
                statuses.append({
                    "id": "LA",
                    "name": "Local Administrator Accounts",
                    "status": "Pass",
                    "description": f"Administrator account configuration is acceptable. Admin count: {admin_count}"
                })

    return {
        "scan_timestamp": datetime.now(UTC).isoformat(),
        "system": system_info,
        "findings": findings,
        "statuses": statuses,
        "errors": errors,
        "debug": debug
    }


def run_mac(cmd):
    """Run a shell command on macOS and return its stdout."""
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except:
        return ""

def run_mac_checks():
    """Run macOS-specific security checks using native shell commands."""
    results = {}

    # CHECK 1: Application Firewall
    fw = run_mac("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
    results["firewall"] = {
        "ok": "enabled" in fw.lower(),
        "data": {"enabled": "enabled" in fw.lower(), "evidence": fw or "No output"},
        "error": None,
        "debug": {}
    }

    # CHECK 2: SSH Remote Login
    ssh = run_mac("systemsetup -getremotelogin 2>/dev/null")
    results["rremote"] = {
        "ok": "off" in ssh.lower(),
        "data": {"Enabled": "on" in ssh.lower(), "evidence": ssh or "Off"},
        "error": None,
        "debug": {}
    }

    # CHECK 3: System Integrity Protection
    sip = run_mac("csrutil status")
    results["sip"] = {
        "ok": "enabled" in sip.lower(),
        "data": {"enabled": "enabled" in sip.lower(), "evidence": sip or "No output"},
        "error": None,
        "debug": {}
    }

    # CHECK 4: FileVault disk encryption
    fv = run_mac("fdesetup status")
    results["filevault"] = {
        "ok": "on" in fv.lower(),
        "data": {"enabled": "on" in fv.lower(), "evidence": fv or "No output"},
        "error": None,
        "debug": {}
    }

    return results


def build_mac_contract(results):
    """Process macOS check results into the standard scan report format."""
    findings = []
    statuses = []

    # Firewall
    fw_data = results["firewall"]["data"]
    if fw_data["enabled"]:
        statuses.append({"id": "FW", "name": "macOS Firewall", "status": "Pass", "description": fw_data["evidence"]})
    else:
        findings.append({
            "id": "FW-001", "name": "Firewall Disabled", "severity": "High",
            "description": "macOS Application Firewall is disabled.",
            "evidence": fw_data["evidence"],
            "remediation": "Go to System Settings > Network > Firewall and enable it."
        })
        statuses.append({"id": "FW", "name": "macOS Firewall", "status": "Fail", "description": fw_data["evidence"]})

    # SSH
    ssh_data = results["rremote"]["data"]
    if ssh_data["Enabled"]:
        findings.append({
            "id": "SSH-001", "name": "SSH Remote Login Enabled", "severity": "Medium",
            "description": "Remote login via SSH is enabled — potential attack surface.",
            "evidence": ssh_data["evidence"],
            "remediation": "Disable via System Settings > General > Sharing > Remote Login."
        })
        statuses.append({"id": "SSH", "name": "SSH Remote Login", "status": "Fail", "description": ssh_data["evidence"]})
    else:
        statuses.append({"id": "SSH", "name": "SSH Remote Login", "status": "Pass", "description": ssh_data["evidence"] or "Disabled"})

    # SIP
    sip_data = results["sip"]["data"]
    if sip_data["enabled"]:
        statuses.append({"id": "SIP", "name": "System Integrity Protection", "status": "Pass", "description": sip_data["evidence"]})
    else:
        findings.append({
            "id": "SIP-001", "name": "SIP Disabled", "severity": "Critical",
            "description": "System Integrity Protection is disabled — core system files are unprotected.",
            "evidence": sip_data["evidence"],
            "remediation": "Boot into Recovery Mode and run: csrutil enable"
        })
        statuses.append({"id": "SIP", "name": "System Integrity Protection", "status": "Fail", "description": sip_data["evidence"]})

    # FileVault
    fv_data = results["filevault"]["data"]
    if fv_data["enabled"]:
        statuses.append({"id": "FV", "name": "FileVault Encryption", "status": "Pass", "description": fv_data["evidence"]})
    else:
        findings.append({
            "id": "FV-001", "name": "FileVault Disabled", "severity": "High",
            "description": "FileVault disk encryption is off — data is unencrypted.",
            "evidence": fv_data["evidence"],
            "remediation": "Enable via System Settings > Privacy & Security > FileVault."
        })
        statuses.append({"id": "FV", "name": "FileVault Encryption", "status": "Fail", "description": fv_data["evidence"]})

    return {
        "scan_timestamp": datetime.now(UTC).isoformat(),
        "system": {
            "hostname": socket.gethostname(),
            "windows_version": platform.platform()
        },
        "findings": findings,
        "statuses": statuses,
        "errors": [],
        "debug": {}
    }


def main():
    # Run the appropriate checks based on the current operating system
    if platform.system() == "Windows":
        results = {}
        for check_name, script_name in SCRIPTS.items():
            results[check_name] = run_powershell_script(script_name)
        contract = build_final_contract(results)
    else:
        print("Running on macOS - using native checks", file=sys.stderr)
        results = run_mac_checks()
        contract = build_mac_contract(results)

    # Output JSON to stdout so the C++ server can capture and parse it
    sys.stdout.write(json.dumps(contract, separators=(",", ":")))
    sys.stdout.flush()

if __name__ == "__main__":
    main()
