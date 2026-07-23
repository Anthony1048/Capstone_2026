# This script inspects the status of all Windows Firewall profiles (Domain, Private, and Public).
# It confirms whether each profile is enabled or disabled to assess network protection.
$ErrorActionPreference = 'Stop'
try {
    # Retrieve firewall profiles (Name + Enabled only)
    $profiles = Get-NetFirewallProfile -ErrorAction Stop |
        Select-Object Name, Enabled

    # Ensure $profiles is always an array
    if ($profiles -eq $null) { $profiles = @() }

    # Success output structure (STRICT format)
    $output = @{
        check = "firewall"
        ok    = $true
        data  = $profiles
        error = $null
    }

    # Output compressed JSON only
    $output | ConvertTo-Json -Compress -Depth 4
}
catch {
    # Failure output structure (STRICT format)
    $output = @{
        check = "firewall"
        ok    = $false
        data  = @()
        error = $_.Exception.Message
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
