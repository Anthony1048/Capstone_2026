# This script checks the status of BitLocker drive encryption on all mounted volumes.
# It reports back whether protection is active and the current volume status in JSON format.
$ErrorActionPreference = 'Stop'
try {
    $volumes = Get-BitLockerVolume -ErrorAction Stop |
        Select-Object MountPoint, VolumeStatus, ProtectionStatus

    $output = @{
        check = "bitlocker"
        ok    = $true
        data  = $volumes
        error = $null
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
catch {
    $output = @{
        check = "bitlocker"
        ok    = $false
        data  = $null
        error = $_.Exception.Message
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
