# This script checks the Windows Registry to see if Remote Desktop (RDP) connections are allowed.
# It specifically looks at the 'fDenyTSConnections' value to determine the access state.
$ErrorActionPreference = 'Stop'
try {
    $rdpValue = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
                                  -Name "fDenyTSConnections" -ErrorAction Stop

    $enabled = ($rdpValue.fDenyTSConnections -eq 0)

    $data = @{
        RDPEnabled = $enabled
        RegistryValue = $rdpValue.fDenyTSConnections
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
