# GPOMap - Active Directory GPO Enumeration & Abuse Detection Tool

## Overview

**GPOMap** is a comprehensive PowerShell tool for auditing and enumerating Group Policy Objects (GPOs) in Active Directory environments. It helps red and blue teams identify misconfigurations, risky permissions, and potential privilege escalation paths through GPO abuse.

Designed for post-exploitation, internal auditing, or AD hardening efforts, this tool provides deep visibility into:

- GPO configurations and ownership
- GPO permissions and delegation rights
- Linked and unlinked GPOs
- GPO contents (scripts, scheduled tasks, software deployments)
- Weak SYSVOL permissions
- Privilege escalation opportunities (direct and indirect)

---

## Key Capabilities

- **Module Availability Checks**
  - Uses `Import-Module` to test whether `GroupPolicy` and `ActiveDirectory` modules are available.
  - Skips checks gracefully if a module is missing.

- **Full GPO Enumeration**
  - Uses `Get-GPO -All` to enumerate all GPOs.
  - Metadata includes: Name, ID, owner (via SID resolution), creation/modification time, and enabled states.

- **Permission Analysis**
  - `Get-GPPermissions -All` is used to list all trustees and their permission levels.
  - Flags "Edit", "Modify", or "GpoEdit" rights as abuse vectors.

- **GPO Content Extraction**
  - `Get-GPOReport -ReportType Xml` extracts ScheduledTasks, Scripts, and SoftwareInstallations from GPO XML data.

- **SYSVOL Permissions Audit**
  - Dynamically builds UNC path for each GPO in SYSVOL.
  - Uses `Get-Acl` to detect non-secure write permissions for users/groups.

- **GPO Link Mapping**
  - Uses `Get-GPInheritance` against Domain and OUs to identify linked GPOs and their status.

- **Delegation Rights**
  - Applies `Get-Acl` on `AD:` PSDrive to discover `CreateChild`, `WriteProperty`, and `GenericAll` rights on OUs.

- **Privilege Escalation Checks**
  - Direct: checks whether the current user has modification rights on Domain/OUs.
  - Indirect: identifies if the user can control users/groups with GPO write rights.

---

## Advantages

- **All-in-one** GPO auditing and attack surface mapping tool.
- **Command-line friendly**: Easy to use in red team, audit, or automated scripts.
- **No dependencies beyond RSAT**.
- **Includes direct and indirect privilege escalation logic**.
- **Color-coded output** for quick visual parsing.

---

## Requirements

- Windows system with **PowerShell**
- The following RSAT modules:
  - `GroupPolicy`
  - `ActiveDirectory`

---

## 🚀 Usage

```powershell
PS C:\> .\GPOMap.ps1
```

The tool will automatically enumerate all possible data and alert you on missing modules or issues.

---

## Sample Output

### GPOs
```text
Name                     EnabledUser EnabledComputer Owner                    Created              Modified
----                     ----------- ---------------- -----                    -------              --------
Default Domain Policy    True        True             CORP\Domain Admins      2022-01-01 10:00:00  2024-01-01 09:15:30
Insecure Scripts         True        False            CORP\ITTeamUser1        2021-05-15 11:22:33  2023-07-20 16:00:00
Password Deployment      False       True             CORP\SecurityOps        2020-03-12 08:13:22  2023-01-10 10:30:55
Legacy GPO               True        True             CORP\GPO_Admins         2018-07-30 11:45:01  2019-12-01 09:01:00
Drive Mapping            True        False            CORP\SupportUser        2021-10-22 13:37:20  2022-09-15 17:44:10
AutoLogon Config         True        False            CORP\HelpDeskUser       2022-06-01 09:12:45  2022-12-01 11:00:00
Test Policy              False       True             CORP\Intern123          2023-01-01 08:00:00  2023-06-01 08:30:00
Custom GPO 7             True        True             CORP\UserBackupAdmin    2022-03-18 15:15:15  2024-03-18 16:30:00
```

### GPO Permissions
```text
GPO                  Trustee               Permission     Type
---                  -------               ----------     ----
Insecure Scripts     CORP\IT Users         GpoEdit        Allow
Password Deployment  CORP\HelpDesk         Modify         Allow
Default Domain       CORP\Domain Admins    GpoEdit        Allow
Drive Mapping        CORP\ITTeamUser1      Modify         Allow
AutoLogon Config     CORP\SupportUser      GpoEdit        Allow
Test Policy          CORP\Interns          GpoRead        Allow
Custom GPO 7         CORP\UserBackupAdmin  GpoEdit        Allow
Legacy GPO           CORP\Contractors      GpoRead        Allow
```

### Abuse Opportunities
```text
[!] CORP\IT Users can modify Insecure Scripts
[!] CORP\SupportUser can modify AutoLogon Config
[!] CORP\HelpDesk can modify Password Deployment
[!] CORP\ITTeamUser1 can modify Drive Mapping
[!] CORP\UserBackupAdmin can modify Custom GPO 7
```

### SYSVOL Weak Permissions
```text
GPO                    Trustee               Rights
---                    -------               ------
Insecure Scripts       Everyone              WriteData, AppendData
Password Deployment    CORP\HelpDesk         Modify, Write
Drive Mapping          CORP\ITTeamUser1      WriteAttributes
AutoLogon Config       Authenticated Users   Write, Delete
Test Policy            CORP\Intern123        Write, Modify
Legacy GPO             CORP\Interns          WriteData
```

### Linked GPOs
```text
GPO                     Target     TargetName                Enforced Enabled
---                     ------     -----------               -------- -------
Default Domain Policy   Domain     corp.local                True     True
Insecure Scripts        OU         Workstations              False    True
Password Deployment     OU         Tier0Admins               True     True
Drive Mapping           OU         Finance                   False    True
AutoLogon Config        OU         Laptops                   False    True
Legacy GPO              OU         LegacyDevices             False    False
Logon Scripts GPO       OU         Sales                     False    True
Custom GPO 7            OU         BackupServers             True     True
```

### Unlinked GPOs
```text
Name                  Owner                  Created              Modified
----                  -----                  -------              --------
Old Laptop Baseline   CORP\GPO_Admins        2020-10-15 08:00:00  2021-02-01 12:05:00
Redundant GPO         CORP\SecurityOps       2019-04-11 10:00:00  2020-01-15 15:30:00
Unused Policy         CORP\IT_Admins         2021-08-01 11:00:00  2021-09-01 10:45:00
Test Deployment       CORP\DevTeam           2022-03-20 14:22:00  2022-03-21 09:00:00
Intern GPO            CORP\Intern123         2023-01-10 09:00:00  2023-01-15 09:15:00
```

### OU Delegation Rights
```text
OU                Trustee             Rights                         Type
--                -------             ------                         ----
Workstations      CORP\IT_Admins      CreateChild, WriteProperty     Allow
Tier0Admins       CORP\SecurityOps    GenericAll                     Allow
Finance           CORP\FinanceLead    WriteProperty                  Allow
Laptops           CORP\HelpDeskUser   CreateChild                    Allow
LegacyDevices     CORP\LegacyTeam     GenericAll                     Allow
HQ-Users          CORP\IT Users       WriteProperty                  Allow
Sales             CORP\SalesMgr       GenericAll                     Allow
BackupServers     CORP\UserBackupAdmin CreateChild, WriteProperty    Allow
```

### Direct Escalation (User Rights on AD Objects)
```text
[+] User has CreateChild on DC=corp,DC=local
[+] User has WriteProperty on OU=Finance,DC=corp,DC=local
[+] User has GenericAll on OU=Workstations,DC=corp,DC=local
[+] User has WriteProperty on OU=HQ-Users,DC=corp,DC=local
[+] User has GenericAll on OU=Sales,DC=corp,DC=local
[+] User has WriteDacl on OU=BackupServers,DC=corp,DC=local
```

### Indirect Escalation (Controlling Privileged Objects)
```text
[!] Current user can control privileged object CORP\GPO_Admins via WriteProperty
[!] Current user can control privileged object CORP\Tier0Maintainers via WriteDacl
[!] Current user can control privileged object CORP\HelpDeskUser via GenericAll
[!] Current user can control privileged object CORP\FinanceLead via WriteDacl
[!] Current user can control privileged object CORP\UserBackupAdmin via WriteProperty
[!] Current user can control privileged object CORP\ITTeamUser1 via WriteDacl
[!] Current user can control privileged object CORP\SupportUser via GenericAll
```

---

## Future Enhancements

- Export results to CSV/HTML.
- Visual mapping of GPO links.
- Integration with BloodHound-compatible output.

---

## License

MIT License

---

## Author

Built with ❤️ for offensive and defensive security use cases.
Contributions welcome!
