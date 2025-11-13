<#
.SYNOPSIS
    A PowerShell tool for editing user privileges stored in Group Policy. 

.DESCRIPTION
    This tool is designed to grant user rights privileges to users, groups, and computers on a domain. 

    

    Requirments:
    - Group Policy PowerShell Module
.PARAMETER Mode
    Determines which mode the tool will run in.
    Aliased to -M
    GetPrivileges: Default mode. Will return a list of privileges that the user has and some examples of how they can be used.
    SysvolEdit: Edits GPOs by modifying their files in the domain's sysvol folder. Takes effect as soon as Group Policy is reloaded.
    BackupEdit: Edits a backup of the GPOs stored on the domain. Takes effect after GPOs are restored from modified backup.

.PARAMETER InputDirectory
    The directory containing GPO backups to be modified.
    Required for Backup Edit mode.
    Aliased to -D
    The provided directory should be the topmost directory of the backup, where the manifest.xml file was created.

.PARAMETER BackupOperator
    Not implemented 
    Performs operation as if done by a backup operator.
    Aliased to -BO
    Requires SeBackupPrivilege and SeRestorePrivilege

.PARAMETER TakeOwn
    Not implemented
    Performs operations by taking ownership of important files
    Aliased to -TO
    Requires SeTakeOwnershipPrivilege

.PARAMETER GPOIdentities
    Parameter that specifies the identities of the GPOs to be operated on.
    Aliased to -GPO.
    Takes in an array of strings. GPO Identities can be provided as a GPO's name or GUID.
    Example: -GPO "Default Domain Policy"

.PARAMETER Identities
    Parameter that specifies the identities to be added to the privilege rights.
    Aliased to -Id.
    Takes in an array of strings. Identities can be formatted as either distinguished names, SIDs, or GUIDs.
    Example: -Identities "user1","group1","S-1-5-32-544","computer1"
    The provided identities can be any user, group, or computer on the domain.

.PARAMETER Privileges
    Parameter that specifies the privileges to be assigned in the privilege rights.
    Aliased to -P.
    Takes in an array of strings. Valid privileges can be found at: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment 
    Example: -Privileges "SeShutdownPrivilege","SeInteractiveLogonRight"

.EXAMPLE
    C:\PS> Add-GPOPrivilege -Mode SysvolEdit -GPO "Default Domain Policy" -Identities "Domain Admins" -Privileges "SeInteractiveLogonRight"

.NOTES
    Author: Josh Kimmel
    Date: July 2025

.LINK
    https://github.com/
#>
[CmdletBinding()]
param 
(
    [ValidateSet("", "GetPrivileges", "SysvolEdit", "BackupEdit")]
    [Alias("M")]
    [string]$mode,

    [Alias("D")]
    [string]$InputDirectory,

    [Alias("BO")]
    [switch]$BackupOperator,
    
    [Alias("TO")]
    [switch]$TakeOwn,

    [Alias("Gpo")]
    [System.Array]$GPOIdentities,

    [Alias("Id")]
    [System.Array]$Identities,

    [Alias("P")]
    [System.Array]$Privileges

)

#Determines which mode to run in an returns the function for that mode
function Get-Mode
{
    param
    (
        [string]$mode
    )


    switch($mode)
    {
        "" 
        {
            Write-Host ("No mode selected, defaulting to Get-Privileges mode")
            return (${function:Get-Privileges})
            break
        }

        "GetPrivileges"
        {
            Write-Host ("Continuing in Get-Privileges mode.")
            return (${function:Get-Privileges})
            break
        }

        "SysvolEdit"
        {
            Write-Host ("Continuing in Edit Sysvol mode.")
            return (${function:Start-SysvolEdit})
            break
        }

        "BackupEdit"
        {
            Write-Host ("Continuing in Edit Backup mode.")
            return (${function:Start-GPOBackupEdit})
            break
        }

        default
        {
            Write-Host ("Too many modes selected, use only one.")
            exit
            break
        }
    }
}

#Gets a list of SIDs for all valid idienties to add to the GPOs 
function Get-SidArray
{
    param
    (
        [System.Array]$identityArray
    )

    $sidArray = @()

    foreach($identity in $identityArray)
    {

        #If an SID or GUID are given, convert them into distinguished names
        $sidName = ([ADSI]"LDAP://<SID=$identity>").distinguishedName
        $guidName = ([ADSI]"LDAP://<GUID=$identity>").distinguishedName

        #If distingusihed names are unable to be found, these values cannot be $null or the LDAP Filter will not work
        if($null -eq $sidName)
        {
            $sidname = $identity
        }
        if($null -eq $guidName)
        {
            $guidname = $identity
        }


        #Gets all users, groups, and computers that match the given identity value
        #Searches based on SamAccountName and DistinguishedName gotten from ADSI LDAP searches
        #https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax
        $adObject = Get-ADObject -LDAPFilter `
        ("(&(|(ObjectClass=user)(ObjectClass=Group)(ObjectClass=Computer))"+
        "(|(SamAccountName=*$identity*)(DistinguishedName=$sidname)"+
        "(DistinguishedName=$guidname)))") -Properties ObjectSID 
        $sidArray += $adObject.ObjectSID.value
    }

    Write-Host ("Adding " + $sidArray.Length + " identities to GPOs." )
    return $sidArray

}

#------------------------------------------------------------------------------#
#Validates and returns all of the GPO's for the provided GPO identities 
function Get-GPOArray
{
    param 
    (
        [System.Array]$gpoIdentityArray
    )
    
    $gpoArray = @()

    #Attempts to match a GPO's GUID then a GPO's name 
    foreach($identity in $gpoIdentityArray)
    {
        if($identity -match "^[A-Fa-f0-9]+-[A-Fa-f0-9]+-[A-Fa-f0-9]+-"+
        "[A-Fa-f0-9]+-[A-Fa-f0-9]+$")
        {
            try
            {
                $gpoArray += Get-GPO -Guid $identity -ErrorAction Stop
            }
            catch
            {
                Write-Host ("Could not find GPO: " + $identity)
            }

        }
        else
        {
            try
            {
                $gpoArray += Get-GPO -Name $identity -ErrorAction Stop
            }
            catch
            {
                Write-Host ("Could not find GPO: " + $identity)
            }
        }
    }

    Write-Host ("Operating on " + $gpoArray.Length + " GPOs")
    return $gpoArray
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

    Write-Host ("Adding " + $privilegeArray.length + " privileges")
    return $privilegeArray
}

#Gets the privileges of the user running the script the same as "whoami /priv".
#Lists some ways to exploit those privileges, including how they can be used with this script.
function Get-Privileges
{
    param
    (
        [string]$thing
    )

    $whoami = whoami /priv

    foreach($line in $whoami)
    {
        if($line[0] -eq "S")
        {
            Write-Host ($Script:privilegeHashTable[$line.substring(0, `
            $line.IndexOf(" "))])
        }
    }
}

#Gets the paths to the rights assignment file (GptTmpl.inf) for all given GPOs 
function Get-RightsAssignmentPaths
{
    param
    (
        [System.Array]$gpoArray
    )

    $rightsAssignmentPaths = @()

    $domain = (Get-ADDomain).forest

    foreach($gpo in $gpoArray)
    {

        $gpoDirectory = `
        ("\\" + $domain + "\SYSVOL\" + $domain + "\Policies\{" + $gpo.id + "}")
        
        $rightsAssignmentDirectory = `
        ($gpoDirectory + "\Machine\Microsoft\Windows NT\SecEdit\")

        $rightsAssignmentFile = `
        ($rightsAssignmentDirectory + "GptTmpl.inf")


        if(Test-Path -Path $rightsAssignmentFile)
        {
            $rightsAssignmentPaths += $rightsAssignmentFile
        }
        else
        {
            $rightsAssignmentPaths += New-RightAssignmentFile -Path `
            $rightsAssignmentFile -Mode $mode
        }

    }

    return $rightsAssignmentPaths
}
#------------------------------------------------------------------------------#
#Creates a new rights assignment file (GptTmpl.inf) if a GPO does not already have it
#
function New-RightAssignmentFile
{
    param
    (
        [string]$path
    )

    $rightsAssignmentStarter = `
    "[Unicode]`r`n" +
    "Unicode=yes`r`n" +
    "[Version]`r`n" +
    'signature="$CHICAGO$"' + "`r`n" +
    "Revision=1`r`n" +
    "[Privilege Rights]"

    $splitPath = $path.Split("\")
    $pathBuilder = ""
    foreach($pathElement in $splitPath)
    {

        $pathBuilder += ("\" + $pathElement)
        $pathBuilder = $pathBuilder.Replace("\\\","\\")

        if(-not (Test-Path $pathBuilder -ErrorAction SilentlyContinue) `
        -and $pathElement -ne "GptTmpl.inf")
        {
            New-Item -Path $pathBuilder -ItemType Directory `
            -ErrorAction SilentlyContinue
        }
        elseif(-not (Test-Path $pathBuilder))
        {
            New-Item -Path $pathBuilder -ItemType File 
            Set-Content -Path $pathBuilder -Value $rightsAssignmentStarter `
            -Encoding "Unicode" -ErrorAction SilentlyContinue
        }
    }
    
    Write-Host $pathBuilder
    return $pathBuilder 
}


#------------------------------------------------------------------------------#
#Starts editing the given GPOs by writing to their rights assignment file (Gpt.inf) in the SYSVOL folder
#GPO files can be found in: \\[domain]\sysvol\[domain]\policies\
function Start-SysvolEdit
{
    param
    (
        [System.Array]$gpoArray,
        [System.Array]$privilegeArray,
        [System.Array]$sidArray
    )

    
    $rightsAssignmentPaths = Get-RightsAssignmentPaths -GpoArray $gpoArray

    foreach($gpo in $rightsAssignmentPaths)
    {
        Write-Sysvol -Path $gpo -PrivilegeArray $privilegeArray `
        -SidArray $sidArray
    } 
    
}

#------------------------------------------------------------------------------#
#Edits a SYSVOL file for a given GPO
#
#This requires permissions to read and write to the SYSVOL files. 
#Defaulting to Domain Administrators and Enterprise Administrators  
function Write-Sysvol
{ 
    param
    (
        [string]$path,
        [System.Array]$privilegeArray,
        [System.Array]$sidArray
    )

    $rightsAssignment = Get-Content -Path $path

    $newRightsAssignment = ""
    $completedArray = (@($false) * $privilegeArray.Length) 


    #creating new file contents
    foreach($line in $rightsAssignment)
    {

        $newRightsAssignment += ($line)

                
        foreach($privilege in $privilegeArray)
        {
            if(($line.IndexOf($privilege) -ne -1))
            {
                $completedArray[$privilegeArray.IndexOf($privilege)] = $true   
                foreach($sid in $sidArray)
                {
                    if(($line.IndexOf($sid) -eq -1))
                    {
                        $newRightsAssignment += (",*" + $sid)
                    }
                }
            }

            elseif((-not $completedArray[$privilegeArray.IndexOf($privilege)]) `
            -and ($line.equals($rightsAssignment[$rightsAssignment.Length - 1])))
            {
                $newRightsAssignment += ("`r`n" + $privilege + " = ")
                foreach($sid in $sidArray)
                {
                    $newRightsAssignment += ("*" + $sid + ",")
                }
            }

            if($newRightsAssignment.Substring($newRightsAssignment.Length - 1,`
            1).equals(","))
            {
                $newRightsAssignment = $newRightsAssignment.Substring(0, `
                $newRightsAssignment.Length - 1)
            }
                    
        }            

        $newRightsAssignment += ("`r`n")   
                     
    }
        
    $newRightsAssignment = $newRightsAssignment.replace("`r`n`r`n`r`n","")
    Set-Content -Path $path -Value $newRightsAssignment -Encoding "unicode"

}



#------------------------------------------------------------------------------#
#Starts editing the given GPOs by writing to their rights assignment file (Gpt.inf) in a backup 
function Start-GPOBackupEdit
{
    param
    (   
        [System.Array]$gpoArray,
        [System.Array]$privilegeArray,
        [System.Array]$sidArray,
        [string]$inputPath
    )

    if(-not (Test-Path -Path $inputPath))
    {
        exit
    }

    $manifestBackupMap = [xml](Get-Content -Path ($inputPath + "\manifest.xml"))
    $backupMap = @{}
    
    foreach($gpo in $ManifestBackupMap.backupinst)
    {
        $guid = $manifestBackupMap.GPOGuid.innerText
        $backupId = $manifestBackupMap.GPO.innerText
        $backupMap.Add($guid, $backupId)
    }


    foreach($gpo in $gpoPathArray)
    {
        Write-GpoBackup -GPO $gpo -PrivilegeArray $privilegeArray `
        -SidArray $sidArray 
    }
    
}
#------------------------------------------------------------------------------#
#Edits the backup for a given GPO
#
#This requires permissions to read and write to the folder with the backups
#Defaulting to whoever created the backups. 
#Backups can be created by anyone with read permissions to the GPOs
function Write-GpoBackup
{
    param
    (   
        [System.Array]$privilegeArray,
        [System.Array]$sidArray,
        [string]$path,
        [string]$mode
    )

    $rightsAssignmentFile = `
    $path + "\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"

    if(Test-Path -Path $rightsAssignmentFile)
    {
        $rightsAssignment = Get-Content ($rightsAssignmentFile)
    }
    else
    {
        New-RightAssignmentFile -Path $rightsAssignmentFile.Substring() `
        -Mode $mode
    }
    

    Write-Sysvol -GpoPath $rightsAssignment -PrivilegeArray $privilegeArray `
    -SidArray $sidArray

    
}
#------------------------------------------------------------------------------#
#Main
$modeFunction = (Get-Mode -Mode $mode)

$gpoArray = Get-GPOArray -GPOIdentityArray $GPOIdentities
$sidArray = Get-SidArray -IdentityArray $identities
$privilegeArray = Get-PrivilegeArray -Privileges $privileges


& $modeFunction -GpoArray $gpoArray -SidArray $sidArray `
-PrivilegeArray $privilegeArray -InputPath $inputDirectory
