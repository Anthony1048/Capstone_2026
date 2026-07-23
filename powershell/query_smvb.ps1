# This script checks if the legacy and insecure SMBv1 protocol is enabled on the system.
# Disabling SMBv1 is a critical security step to prevent older network-based attacks.
$ErrorActionPreference = 'Stop'
try {
    $smb = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop

    $data = @{
        FeatureName = $smb.FeatureName
        State       = $smb.State
        Enabled     = ($smb.State -eq "Enabled")
    }

    $output = @{
        check = "smbv1"
        ok    = $true
        data  = $data
        error = $null
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
catch {
    $output = @{
        check = "smbv1"
        ok    = $false
        data  = $null
        error = $_.Exception.Message
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
