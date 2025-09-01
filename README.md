# Windows Permission Management PowerShell Tools

***
## Table of Contents
[Windows Permission Management PowerShell Tool](#windows-permission-management-powershell-tool)
1. [About the Project](#about-the-project)
	- [Invoke-PrivilegeAudit](#invoke-privilegeaudit)
	- [Edit-GPO](#edit-gpo)
	- [Get-LocalPrivilegeAudit](#get-localprivilegeaudit)
	- [Edit-LocalPrivilege](#edit-localprivilege)
2. [Usage](#usage)
3. [License](#license)


[Back to Top](#windows-permission-management-powershell-tool)
***

## About the Project

This project contains several scripts to audit and modify user rights assignment security policy settings on Windows systems and domains. A detailed list of these rights and what they do can be found [here](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment). 


[Back to Top](#windows-permission-management-powershell-tool)
***

## Usage

Download scripts individually or clone the entire repository. 

```sh
git clone https://github.com/Josh-Kimmel/Windows-Permission-Management-Powershell-tool/
```




For detailed information on each script, view their help page with the `Get-Help` PowerShell command.

#### Invoke-PrivilegeAudit

`Invoke-PrivilegeAudit.ps1`

Performs an audit of one or more Group Policy Objects' user rights assignment security policy settings. Also contains utilities for backing up and restoring Group Policy Objects with more usability than the default PowerShell tools.  Can optionally output its results to a file. 

Must be run on a domain-joined system with the Group Policy PowerShell module installed.

#### Edit-GPO

`Edit-GPO.ps1`

Grants privileges to users, groups, and computers on a domain by editing one or more Group Policy Objects' user rights assignment security policy settings. 

Must be run on a domain-joined system with the Group Policy PowerShell module installed.

#### Get-LocalPrivilegeAudit

`Get-LocalPrivilegeAudit.ps1`

Performs an audit of the local system's user rights assignment security policy settings in its secedit database. Returns a table of all privileges granted to all users and groups on the computer. Can output its results to a CSV file. 

Must be run as Administrator or have a secedit configuration file in the running directory. This file can be generated with the following command:

```Powershell
secedit /export /cfg secpol.cfg
```


#### Edit-LocalPrivilege 

`Edit-LocalPrivilege.ps1`

Grants privileges to users and groups on the local system by editing its user rights assignment security policy settings in its secedit database. 

Must be run as Administrator or other user or group with access to the secedit command line utility. 


[Back to Top](#windows-permission-management-powershell-tool)
***

## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

[Back to Top](#windows-permission-management-powershell-tool)
***




