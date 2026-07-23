# This script performs a comprehensive check for Remote Desktop, including service and firewall status.
# It verifies if the RDP service is running and if the necessary firewall rules are active.
$ErrorActionPreference = 'Stop'
try {

    $rdpValue = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
                                 -Name "fDenyTSConnections" -ErrorAction Stop

    $registryEnabled = ($rdpValue.fDenyTSConnections -eq 0)

    $service = Get-Service -Name "TermService" -ErrorAction Stop
    $serviceRunning = ($service.Status -eq "Running")

    $firewallRule = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue |
                    Where-Object { $_.Enabled -eq "True" }

    $firewallEnabled = ($firewallRule.Count -gt 0)

    $data = @{
        RDPActive       = ($registryEnabled -and $serviceRunning -and $firewallEnabled)
        RegistryEnabled = $registryEnabled
        ServiceRunning  = $serviceRunning
        FirewallEnabled = $firewallEnabled
    }

    $output = @{
        check = "rdp"
        ok    = $true
        data  = $data
        error = $null
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
catch {

    $output = @{
        check = "rdp"
        ok    = $false
        data  = $null
        error = $_.Exception.Message
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
