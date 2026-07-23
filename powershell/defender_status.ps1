# This script retrieves the status of Windows Defender and other installed antivirus products.
# It checks for real-time protection and the last timestamp for signature updates.
$ErrorActionPreference = 'Stop'
try {

    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue

    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" `
                                  -ClassName "AntivirusProduct" `
                                  -ErrorAction SilentlyContinue

    $avList = $avProducts | ForEach-Object {
        @{
            Name = $_.displayName
            Path = $_.pathToSignedProductExe
        }
    }

    $data = @{
        DefenderEnabled = $defender.AntivirusEnabled
        RealTimeProtection = $defender.RealTimeProtectionEnabled
        SignatureLastUpdated = $defender.AntivirusSignatureLastUpdated
        InstalledAntivirus = $avList
    }

    $output = @{
        check = "antivirus"
        ok    = $true
        data  = $data
        error = $null
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
catch {

    $output = @{
        check = "antivirus"
        ok    = $false
        data  = $null
        error = $_.Exception.Message
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
