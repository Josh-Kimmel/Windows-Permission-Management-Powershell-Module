<#
.SYNOPSIS
    A Powershell tool for editing user privileges on a local system.

.DESCRIPTION
    This tool is designed to be run as Administrator and cannot be run without it.

    This tool edits the local system's secedit database.
    It adds user rights assignment privileges to the local system for each provided identity.
    
.PARAMETER Identities
    Parameter that specifies the identities to be added to the privilege rights.
    Aliased to -Id.
    Takes in an array of strings. Identities can be formatted as either distinguished names or SIDs.
    Example: -Identities "user1","group1","S-1-5-32-544"
    The provided identities must exist on the local system.

.PARAMETER Privileges
    Parameter that specifies the privileges to be assigned in the privilege rights.
    Aliased to -P.
    Takes in an array of strings. Valid privileges can be found at: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment 
    Example: -Privileges "SeShutdownPrivilege","SeInteractiveLogonRight"

.PARAMETER ComputerNames
    Parameter that specifies the computers to run the tool on.
    Aliased to -C.
    Takes in an array of strings. Computers must be reachable through PSSessions.
    Example: -ComputerNames "computer1","computer2"

.EXAMPLE
    C:\PS> Add-LocalPrivilege -Identities [User1] -Privileges [Privilege]

    Description:
    Gives the provided privilege to the provided user on the local system.
    
.EXAMPLE 
    C:\PS> Add-LocalPrivilege -Identities [User1],[User2] -Privileges [Privilege],[Privilege]

    Description:
    Gives both provided privileges to both the provided users on the local system.

.EXAMPLE
    C:\PS> Add-LocalPrivilege -Identities [User1] -Privileges [Privilege] -ComputerNames [Computer1],[Computer2]

    Description:
    Gives the provided privilege to the provided user on the provided systems, but not the local system.

.NOTES
    Author: Josh Kimmel
    Date: August 2025

.LINK
    https://github.com/Josh-Kimmel/Windows-Permission-Management-Powershell-Module/blob/main/Add-LocalPrivilege.ps1
#>

[CmdletBinding()]
param
(
    [Alias("Id")]
    [System.Array]$Identities,

    [Alias("P")]
    [System.Array]$Privileges,

    [Alias("C")]
    [System.Array]$ComputerNames
)

function Get-SidArray
{
    param
    (
        [System.Array]$identityArray
    )

    $sidArray = @()

    foreach($identity in $identityArray)
    {
        $testIdentity = $null


        for($i = 0; $i -lt 4; $i++)
        {


            switch ($i)
            {
                0
                {
                    $testIdentity = Get-LocalUser -Name $identity `
                    -ErrorAction SilentlyContinue
                    break
                }

                1
                {
                    $testIdentity = Get-LocalUser -Sid $identity `
                    -ErrorAction SilentlyContinue
                    break
                }

                2
                {
                    $testIdentity = Get-LocalGroup -Name $identity `
                    -ErrorAction SilentlyContinue
                    break
                }

                3
                {
                    $testIdentity = Get-LocalGroup -Sid $identity `
                    -ErrorAction SilentlyContinue
                    break
                }
                
            }

            if($null -ne $testIdentity)
            {
                $sidArray += $testIdentity.sid.value
                break
            }
            
        }

    }

    return $sidArray

}

#Table of privileges and descriptions 
#https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment 
$privilegeHashTable = @{
    "SeAssignPrimaryTokenPrivilege" = "Can start process as another user if credentials are known."
    "SeAuditPrivilege" = "Can generate audit-log entries."
    "SeBackupPrivilege" = "Can read any file. This includes sensitive files. Pairs with SeRestorePrivilege for full read and write access across a system."
    "SeChangeNotifyPrivilege" = "Can traverse directories regardless of permissions. Cannot read or write with directory contents with permissions."
    "SeCreateGlobalPrivilege" = "Can create global objects that are available to all sessions. Required for RDP connections."
    "SeCreatePagefilePrivilege" = "Can create paging file."
    "SeCreatePermanentPrivilege" = "Can create permanent objects. This includes AD objects, files, folders, and registry keys."
    "SeCreateSymbolicLinkPrivilege" = "Can create symbolic links."
    "SeCreateTokenPrivilege" = "Can create and modify access tokesn. Can be used to gain complete control over a system"
    "SeDebugPrivilege" = "Attach a debugger to processes."
    "SeDelegateSessionUserImpersonatePrivilege" = "Can obtain impersonation token for other users in the same session."
    "SeEnableDelegationPrivilege" = "Can impersonate other users on a network."
    "SeImpersonatePrivilege" = "Can impersonate other users."
    "SeIncreaseBasePriorityPrivilege" = "Can change the scheduling priority of processes."
    "SeIncreaseQuotaPrivilege" = "Can change the maximum memory used by a process."
    "SeIncreaseWorkingSetPrivilege" = "Can modify the working set of a process."
    "SeLoadDriverPrivilege" = "Can load or unload device drivers. Can be used to install malware that runs with high privileges."
    "SeLockMemoryPrivilege" = "Can lock data in physical memory."
    "SeMachineAccountPrivilege" = "Can add devices to the domain."
    "SeManageVolumePrivilege" = "Can manage disks and storage volumes."
    "SeProfileSingleProcessPrivilege" = "Can monitor process performance."
    "SeRelabelPrivilege" = "Can modify the integrity level of objects owned by other users."
    "SeRemoteShutdownPrivilege" = "Can shutdown a system remotely."
    "SeRestorePrivilege" = "Can write to any file. This includes sensitive files and executables. Pairs with SeBackupPrivilege for full read and write access across a system."
    "SeSecurityPrivilege" = "Can access audit options for individual objects. Can view and clear the Security Log in Event Viewer."
    "SeShutdownPrivilege" = "Can shutdown the system."
    "SeSyncAgentPrivilege" = "Can forcibly synchronize all directory service data."
    "SeSystemEnvironmentPrivilege" = "Can modify firmware environment values."
    "SeSystemProfilePrivilege" = "Can monitor system performance."
    "SeSystemtimePrivilege" = "Can change the system time."
    "SeTakeOwnershipPrivilege" = "Can take ownership of files."
    "SeTcbPrivilege" = "Can act as system. Can be used to take control of a system and erase the evidence."
    "SeTimeZonePrivilege" = "Can change the system timezone."
    "SeTrustedCredManAccessPrivilege" = "Can access credential manager. Can be used to gain access to credentials of other users."
    "SeUndockPrivilege" = "Can remove the device from its docking system and log in afterwards."
    "SeUnsolicitedInputPrivilege" = "Can read unsolicied input from a terminal device."
    "SeBatchLogonRight" = "Can sign in to a device using a batch method, such as Task Scheduler."
    "SeDenyBatchLogonRight" = "Explicitly cannot sign into a device using a batch method."
    "SeDenyInteractiveLogonRight" = "Explicitly cannot start an interactive logon session on the system."
    "SeDenyNetworkLogonRight" = "Explicitly cannot connect to the system through network protocols."
    "SeDenyServiceLogonRight" = "Explicitly cannot start services that run continuously on a system."
    "SeDenyRemoteInteractiveLogonRight" = "Explicitly cannot sign into a device with RDP."
    "SeInteractiveLogonRight" = "Can start an interactive logon session on the system."
    "SeNetworkLogonRight" = "Can connect to the system through network protocols, such as SMB and NetBIOS."
    "SeRemoteInteractiveLogonRight" = "Can sign into a device with RDP."
    "SeServiceLogonRight" = "Can start services that run continuously on a system."
}


#Validates the privileges that the user provides to the script for change. 
#Also corrects mis-capitalization of the privileges to keep them uniform with rest of the privileges
function Get-PrivilegeArray
{
    param
    (
        [System.Array]$privileges
    )
    $privilegeArray = @()

    foreach($privilege in $privileges)
    {
        if($null -ne $Script:privilegeHashTable[$privilege])
        {
            foreach($key in $Script:privilegeHashTable.keys)
            {
                if($key -eq $privilege)
                {
                    $privilegeArray += $key
                    break
                }
            }
        }
    }

    Write-Host ("Adding " + $privilegeArray.length + " privilege(s)")
    return $privilegeArray
}


function Get-PrivilegeLines
{
    param
    (
        [System.Array]$seceditContent
    )

    $privilegeLines = @()

    foreach($line in $seceditContent)
    {
        if($line.substring(0,2).equals("Se"))
        {
            $privilegeLines += ($line)
        }
    }

    return $privilegeLines

}


function Write-PrivilegeContent
{
    param
    (
        [System.Array]$sidArray,
        [System.Array]$privilegeArray,
        [System.Array]$privilegeLines
    )

    $newPrivilegeLines = @()

    foreach($line in $privilegeLines)
    {
        
        $newLine = $line
        foreach($privilege in $privilegeArray)
        {
            if($line -match $privilege)
            {                
                foreach($sid in $sidArray)
                {
                    if(-not($line -match $sid))
                    {
                        $newLine = ($newLine.trim() + ",*" + $sid)
                    }
                }

                $newLine += ("`r`n")

            }
        }
        
        $newPrivilegeLines += $newLine
    
    }

    return $newPrivilegeLines
}



function Start-PrivilegeEdit
{
    param
    (
        [System.Array]$sidArray,
        [System.Array]$privilegeArray
    )

    $isAdmin = ([Security.Principal.WindowsPrincipal]`
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole]::Administrator)

    $currentPath = (Get-Location).ToString()

    if($isAdmin)
    {
        $seceditStatus = secedit /export /cfg ($currentPath + "\secpol.cfg")
        $seceditContent = (Get-Content -Path ($currentPath + "\secpol.cfg") `
        -Delimiter "`r`n")

        $privilegeLines = Get-PrivilegeLines -SeceditContent $seceditContent       

        $newPrivilegeLines = Write-PrivilegeContent -SidArray $sidArray `
        -PrivilegeArray $privilegeArray -PrivilegeLines $privilegeLines
        

        $startPrivilegeIndex = `
        ([string]$seceditContent).IndexOf("[Privilege Rights]")
        $endPrivilegeIndex = `
        (($startPrivilegeIndex + "[Privilege Rights]".Length) + `
        ([string]$privilegeLines).Length)


        $newSeceditContent = ""
        $newSeceditContent += `
        ([string]$seceditContent).Substring(0 , ($startPrivilegeIndex + `
        "[Privilege Rights]".Length)).Trim()
        $newSeceditContent += ("`r`n" + (([string]$newPrivilegeLines).Trim()))
        $newSeceditContent += `
        ("`r`n" + ([string]$seceditContent).Substring($endPrivilegeIndex + 1).Trim())

        Set-Content -Path ($currentPath + "\secpol.cfg") -Value `
        $newSeceditContent.Trim() -Encoding Unicode 
        
        $seceditStatus = `
        secedit /configure /db c:\windows\security\local.sdb /cfg ($currentPath + "\secpol.cfg") /areas SECURITYPOLICY
    }
    


    Remove-Item -Path ($currentPath + "\secpol.cfg") -Force


    
    
}




function Start-RemotePrivilegeEdit
{
    param
    (
        [string]$computerName,
        [System.Array]$sidArray,
        [System.Array]$privilegeArray
    )

    $session = New-PSSession -ComputerName $computerName `
    -ErrorAction SilentlyContinue

    if($null -ne $session)
    {
        Invoke-Command -Session $session -ScriptBlock {Start-PrivilegeEdit `
        -SidArray $Using:sidArray -PrivilegeArray $Using:privilegeArray}
    }
}



#Main

$sidArray = Get-SidArray -identityArray $identities
$privilegeArray = Get-PrivilegeArray -Privileges $privileges

Write-Host $sidArray

if($null -ne $ComputerNames)
{
    foreach ($computer in $ComputerNames)
    {
        Start-RemotePrivilegeEdit -ComputerName $computer `
        -SidArray $sidArray -PrivilegeArray $privilegeArray
    }
}
else
{
    Start-PrivilegeEdit -SidArray $sidArray -PrivilegeArray $privilegeArray
}




