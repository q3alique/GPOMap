# Modules required: GroupPolicy, ActiveDirectory

$canCheckGP    = $false
$canCheckAD    = $false

if (-not $canCheckGP) {
    Write-Warning "The 'GroupPolicy' module is not available. Please install RSAT: Group Policy Management Tools."
}

if (-not $canCheckAD) {
    Write-Warning "The 'ActiveDirectory' module is not available. Please install RSAT: Active Directory Module for Windows PowerShell."
}

function Test-ModuleAvailability {
    param($ModuleName)
    try {
        Import-Module $ModuleName -ErrorAction Stop
        return $true
    } catch {
        Write-Warning "$ModuleName module not available. Skipping related checks."
        return $false
    }
}

function Resolve-SID {
    param ($SID)
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        return $objUser.Value
    } catch {
        return $SID
    }
}

Write-Host "`n[+] Checking module availability..." -ForegroundColor Cyan
$canCheckGP    = Test-ModuleAvailability -ModuleName "GroupPolicy"
$canCheckAD    = Test-ModuleAvailability -ModuleName "ActiveDirectory"

$GPOs = @()
$GPO_Permissions = @()
$GPO_Links = @()
$AbuseFlags = @()
$UnlinkedGPOs = @()
$DelegationRights = @()
$GPO_Contents = @()
$SYSVOL_WeakPerms = @()

if ($canCheckGP) {
    Write-Host "`n[*] Enumerating GPOs..." -ForegroundColor Cyan
    $AllGPOs = Get-GPO -All
    $LinkedGpoNames = @()

    foreach ($gpo in $AllGPOs) {
        $ComputerEnabled = $gpo.GpoStatus -eq 'AllSettingsEnabled' -or $gpo.GpoStatus -eq 'ComputerSettingsEnabled'
        $UserEnabled     = $gpo.GpoStatus -eq 'AllSettingsEnabled' -or $gpo.GpoStatus -eq 'UserSettingsEnabled'

        $GPOs += [PSCustomObject]@{
            Name           = $gpo.DisplayName
            ID             = $gpo.Id
            Owner          = Resolve-SID $gpo.Owner
            Created        = $gpo.CreationTime
            Modified       = $gpo.ModificationTime
            EnabledUser    = $UserEnabled
            EnabledComputer= $ComputerEnabled
            DomainGPO      = $true
        }

        $permissions = Get-GPPermissions -Guid $gpo.Id -All
        foreach ($perm in $permissions) {
            $resolved = Resolve-SID $perm.Trustee.SID
            $GPO_Permissions += [PSCustomObject]@{
                GPO        = $gpo.DisplayName
                Trustee    = $resolved
                Permission = $perm.Permission
                Type       = $perm.PermissionType
            }

            if ($perm.Permission -match 'Edit|GpoEdit|Modify') {
                $AbuseFlags += "[!] $resolved can modify $($gpo.DisplayName)"
            }
        }

        # Parse GPO content for scripts, tasks, etc.
        try {
            $xml = Get-GPOReport -Guid $gpo.Id -ReportType Xml
            if ($xml -and $xml -match '<') {
                $xmlDoc = New-Object System.Xml.XmlDocument
                $xmlDoc.LoadXml($xml)

                $tasks   = $xmlDoc.SelectNodes("//ScheduledTasks/Task")
                $scripts = $xmlDoc.SelectNodes("//Scripts/Script")
                $apps    = $xmlDoc.SelectNodes("//Deployment/Package")

                foreach ($task in $tasks) {
                    $GPO_Contents += [PSCustomObject]@{
                        GPO     = $gpo.DisplayName
                        Type    = "ScheduledTask"
                        Detail  = $task.Name
                    }
                }
                foreach ($script in $scripts) {
                    $GPO_Contents += [PSCustomObject]@{
                        GPO     = $gpo.DisplayName
                        Type    = "Script"
                        Detail  = $script.Command
                    }
                }
                foreach ($app in $apps) {
                    $GPO_Contents += [PSCustomObject]@{
                        GPO     = $gpo.DisplayName
                        Type    = "SoftwareInstall"
                        Detail  = $app.Name
                    }
                }
            }
        } catch {
            Write-Warning "Could not parse GPO Report for $($gpo.DisplayName)"
        }

        # SYSVOL path check
        $domain = (Get-ADDomain).DNSRoot
        $sysvolPath = "\\$domain\SYSVOL\$domain\Policies\{$($gpo.Id)}"
        if (Test-Path $sysvolPath) {
            try {
                $acl = Get-Acl $sysvolPath
                foreach ($entry in $acl.Access) {
                    $trustee = $entry.IdentityReference
                    if ($entry.FileSystemRights -match 'Write' -and $entry.AccessControlType -eq 'Allow') {
                        $resolvedTrustee = Resolve-SID $trustee
                        $SYSVOL_WeakPerms += [PSCustomObject]@{
                            GPO      = $gpo.DisplayName
                            Trustee  = $resolvedTrustee
                            Rights   = $entry.FileSystemRights
                        }
                    }
                }
            } catch {
                Write-Warning "Could not read SYSVOL ACL for $($gpo.DisplayName)"
            }
        }
    }
} else {
    Write-Warning "Skipping GPO enumeration (GroupPolicy module missing)"
}

if ($canCheckAD -and $canCheckGP) {
    Write-Host "`n[*] Checking linked GPOs (Domains, OUs)..." -ForegroundColor Cyan
    $domainDN = (Get-ADDomain).DistinguishedName
    $inheritance = Get-GPInheritance -Target $domainDN
    foreach ($link in $inheritance.GpoLinks) {
        $GPO_Links += [PSCustomObject]@{
            GPO        = $link.DisplayName
            Target     = "Domain"
            TargetName = $domainDN
            Enforced   = $link.Enforced
            Enabled    = $link.Enabled
        }
    }

    $OUs = Get-ADOrganizationalUnit -Filter *
    foreach ($ou in $OUs) {
        $inheritance = Get-GPInheritance -Target $ou.DistinguishedName
        foreach ($link in $inheritance.GpoLinks) {
            $GPO_Links += [PSCustomObject]@{
                GPO        = $link.DisplayName
                Target     = "OU"
                TargetName = $ou.Name
                Enforced   = $link.Enforced
                Enabled    = $link.Enabled
            }
        }

        try {
            $ouAcl = Get-Acl -Path "AD:$($ou.DistinguishedName)"
            foreach ($ace in $ouAcl.Access) {
                if ($ace.ActiveDirectoryRights -match 'CreateChild|WriteProperty|GenericAll') {
                    $DelegationRights += [PSCustomObject]@{
                        OU          = $ou.Name
                        Trustee     = Resolve-SID $ace.IdentityReference
                        Rights      = $ace.ActiveDirectoryRights
                        Type        = $ace.AccessControlType
                    }
                }
            }
        } catch {
            Write-Warning "Could not read ACL for OU $($ou.Name)"
        }
    }

    $LinkedGpoNames = $GPO_Links.GPO | Select-Object -Unique
    foreach ($gpo in $GPOs) {
        if ($LinkedGpoNames -notcontains $gpo.Name) {
            $UnlinkedGPOs += $gpo
        }
    }
} else {
    Write-Warning "Skipping GPO links (missing AD or GP modules)"
}

# Output section
Write-Host "`n[=] GPOs:`n" -ForegroundColor Yellow
$GPOs | Format-Table Name, EnabledUser, EnabledComputer, Owner, Created, Modified

Write-Host "`n[=] Linked GPOs:`n" -ForegroundColor Yellow
$GPO_Links | Format-Table GPO, Target, TargetName, Enforced, Enabled

Write-Host "`n[=] GPO Permissions:`n" -ForegroundColor Yellow
$GPO_Permissions | Format-Table GPO, Trustee, Permission, Type

Write-Host "`n[!] Abuse Opportunities:`n" -ForegroundColor Red
$AbuseFlags | ForEach-Object { Write-Host $_ -ForegroundColor Red }

Write-Host "`n[!] Unlinked GPOs:`n" -ForegroundColor Magenta
$UnlinkedGPOs | Format-Table Name, Owner, Created, Modified

Write-Host "`n[!] OU Delegation Rights:`n" -ForegroundColor Cyan
$DelegationRights | Format-Table OU, Trustee, Rights, Type

Write-Host "`n[=] GPO Contents (Scripts, Tasks, Software):`n" -ForegroundColor Green
$GPO_Contents | Format-Table GPO, Type, Detail

Write-Host "`n[!] SYSVOL Weak Permissions:`n" -ForegroundColor DarkRed
$SYSVOL_WeakPerms | Format-Table GPO, Trustee, Rights

# Privilege Escalation Checks

if ($canCheckAD) {

    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentSID  = $CurrentUser.User.Value

    Write-Host "`n[*] Checking direct GPO rights for current user..." -ForegroundColor Cyan

    function Test-EffectiveRights {
        param (
            [string]$TargetDN
        )
        try {
            $acl = Get-Acl "AD:$TargetDN"
            foreach ($ace in $acl.Access) {
                $sid = $ace.IdentityReference
                if ($sid -eq $CurrentSID -or $sid -eq $CurrentUser.Name) {
                    if ($ace.ActiveDirectoryRights -match "CreateChild|WriteProperty|GenericAll") {
                        Write-Host "[+] User has $($ace.ActiveDirectoryRights) on $TargetDN" -ForegroundColor Yellow
                    }
                }
            }
        } catch {
            Write-Warning "Could not read ACL for $TargetDN"
        }
    }

    try {
        # 1. Domain root
        $domainDN = (Get-ADDomain).DistinguishedName
        Test-EffectiveRights -TargetDN $domainDN

        # 2. All OUs
        $OUs = Get-ADOrganizationalUnit -Filter *
        foreach ($ou in $OUs) {
            Test-EffectiveRights -TargetDN $ou.DistinguishedName
        }
    } catch {
        Write-Warning "Could not complete direct DACL check due to missing or failed AD cmdlets"
    }


    # Indirect Escalation Check

    Write-Host "`n[*] Checking if current user can control users/groups with GPO rights..." -ForegroundColor Cyan

    $PrivilegedSIDs = $GPO_Permissions | Where-Object {
        $_.Permission -match 'Edit|Modify'
    } | ForEach-Object {
        $_.Trustee
    } | Select-Object -Unique

    foreach ($sid in $PrivilegedSIDs) {
        try {
            $object = Get-ADObject -Filter { Name -eq $sid -or SamAccountName -eq $sid } -Properties DistinguishedName, ObjectClass
            if ($object) {
                $acl = Get-Acl "AD:$($object.DistinguishedName)"
                foreach ($ace in $acl.Access) {
                    if ($ace.IdentityReference -eq $CurrentSID -or $ace.IdentityReference -eq $CurrentUser.Name) {
                        if ($ace.ActiveDirectoryRights -match "WriteProperty|GenericAll|WriteDacl") {
                            Write-Host "[!] Current user can control privileged object $($object.Name) via $($ace.ActiveDirectoryRights)" -ForegroundColor Red
                        }
                    }
                }
            }
        } catch {
            Write-Warning "Could not check control over $sid"
        }
    }

} else {
    Write-Warning "Skipping privilege escalation checks (ActiveDirectory module missing)"
}

