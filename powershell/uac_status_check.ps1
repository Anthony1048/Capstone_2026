# This script audits the User Account Control (UAC) settings by checking the 'EnableLUA' registry value.
# It determines if the system will prompt for permission before allowing administrative changes.
$ErrorActionPreference = 'Stop'
try {
    $uacValue = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                                  -Name "EnableLUA" -ErrorAction Stop

    $enabled = ($uacValue.EnableLUA -eq 1)

    $data = @{
        UACEnabled = $enabled
        RegistryValue = $uacValue.EnableLUA
    }

    $output = @{
        check = "uac"
        ok    = $true
        data  = $data
        error = $null
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
catch {
    $output = @{
        check = "uac"
        ok    = $false
        data  = $null
        error = $_.Exception.Message
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
