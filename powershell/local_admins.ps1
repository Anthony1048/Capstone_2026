# This script lists all members currently in the local "Administrators" group.
# It helps identify users with elevated privileges on the system for security auditing.
$ErrorActionPreference = 'Stop'
try {

    $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop

    $adminList = $members | ForEach-Object {
        @{
            Name = $_.Name
            ObjectClass = $_.ObjectClass
            PrincipalSource = $_.PrincipalSource
        }
    }

    $data = @{
        Administrators = $adminList
        Count = $adminList.Count
    }

    $output = @{
        check = "local_admins"
        ok    = $true
        data  = $data
        error = $null
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
catch {

    $output = @{
        check = "local_admins"
        ok    = $false
        data  = $null
        error = $_.Exception.Message
    }

    $output | ConvertTo-Json -Compress -Depth 4
}
