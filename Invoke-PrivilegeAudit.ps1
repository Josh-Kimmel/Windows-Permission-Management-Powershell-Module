<#
.SYNOPSIS
    A PowerShell tool that provides utilities relating to Group Policy and auditing user rights assignments within it.
.DESCRIPTION
    This tool is used for basic administrative tools for Group Policy. 
    The includes backing up Group Policy Objects, restoring Group Policy Objects from backups, and auditing user rights assignments within Group Policy Objects. 

    The audit and backup functions of this tool can be run as any user with read access to Group Policy Objects.
    By default this includes any Authorized User on the domain.

    The restore function of this tool can be run as any user with write access to Group Policy Objects.
    By default this includes the Domain Admins and Enterprise Admins groups and the SYSTEM account.


    Requirments:
    - Group Policy PowerShell Module
.PARAMETER Audit
    Flag that sets Invoke-PrivilegeAudit into audit mode.
    Aliased to -A 
    Audit mode audits the user rights assignments of the provided GPOs.
    This mode requires either the GPOIdentity or AllGPOs parameters specified.
    The file output of this mode produces a text file with the audit results.

.PARAMETER Backup
    Flag that sets Invoke-PrivilegeAudit into backup mode.
    Aliased to -B
    Backup mode backs up the provided GPOs to a provided folder.
    This mode requires either the GPOIdentity or AllGPOs parameters specified and the Output parameter specified.
    The file output of this mode produces folders for each GPO backed up, a manifest.xml file used for restoring the backups, and a text file containg mappings between GPOs and the backups.

.PARAMETER Restore
    Flag that sets Invoke-PrivilegeAudit into restore mode.
    Aliased to -R
    Restore mode restores the provided GPOs from a backup.
    This mode requires either the GPOIdentity or AllGPOs parameters specified and the InputPath parameter specified.
    The file output of this mode produces a text file containing the GPOs that were and were not restored.
    
.PARAMETER GPOIdentity
    Parameter that specifies the identity of a singular GPO to be operated on.
    Aliased to -GPO
    This parameter can be either either be given as a GPO's name or GUID.
    Incompatible with AllGPOs.

.PARAMETER AllGPOs
    Flag that specifices that all GPOs on a domain are going to be operated on.
    Aliased to -All
    Incompatible with GPOIdentity.

.PARAMETER Output
    Parameter that specifies the directory for Invoke-PrivilegeAudit to place its output.
    Aliased to -O 
    The output will alway be contained in a folder with the structure "privAudit-yyyy-MM-dd-HH-mm-ss/".
    The output files vary depending on the mode. 

.PARAMETER InputDirectory
    Parameter that specifies the directory for GPO backups to be taken from.
    Aliased to -I
    Only used for retore mode.

.EXAMPLE
    C:\PS>Invoke-PrivilegeAudit -Audit -GPOIdentity "Default Domain Policy"

    Description:
    Returns a privilege audit of the "Defaut Domain Policy" GPO

.EXAMPLE
    C:\PS>Invoke-PrivilegeAudit -Audit -AllGPOs -Output "C:\"

    Description:
    Writes a privilege audit of all GPOs on a domain to a folder in the "C:\" directory.

.EXAMPLE
    C:\PS>Invoke-PrivilegeAudit -Backup -GPOIdentity "Default Domain Policy" -Output "."

    Description:
    Creates a backup of the "Default Domain Policy" in a folder in the current directory.
    
.EXAMPLE
    C:\PS>Invoke-PrivilegeAudit -Restore -AllGPOs -InputDirectory "C:\privAudit-yyyy-MM-dd-HH-mm-ss"

    Description:
    Restores all GPOs to the versions located in the input directory. If a GPO does not have a backup in the provided directory, it will not be modified.

.NOTES
    Author: Josh Kimmel
    Date: June 2025
.LINK
    https://github.com/
#>
[CmdletBinding()]
param 
(
    [Alias("A")]
    [switch]$Audit = $false,
    #Run in audit mode. Default mode 
    [Alias("B")]
    [switch]$Backup = $false,
    #Run in backup mode.
    [Alias("R")]
    [switch]$Restore = $false,  
    #run in restore mode.

    [Alias("GPO")]
    [string]$GPOIdentity = "",
    #The Identity of the GPO to be acted on. Can be either its name or GUID.
    [Alias("All")]
    [switch]$AllGPOs = $false,
    #Act on all GPOs in the domain

    [Alias("O")]
    [string]$Output,
    #Path of the directory for the output to be placed into.  
    [Alias("I")]
    [string]$Inputdirectory
    #Path of the directory for GPO backups to be taken from
)


#Determines which mode to run in an returns the function for that mode
function Get-Mode
{
    param
    (
        [boolean]$audit,
        [boolean]$backup,
        [boolean]$restore
    )

    $modeValue = 
        ([int][bool]::Parse($audit) * 1) +
        ([int][bool]::Parse($backup) * 2) +
        ([int][bool]::Parse($restore) * 4)

    switch($modeValue)
    {
        0 
        {
            Write-Host ("No mode selected, defaulting to audit mode")
            return (${function:Start-Audit})
            break
        }

        1
        {
            Write-Host ("Continuing in audit mode.")
            return (${function:Start-Audit})
            break
        }

        2
        {
            Write-Host ("Continuing in backup mode.")
            return (${function:Start-Backup})
            break
        }

        4
        {
            Write-Host ("Continuing in restore mode.")
            return (${function:Start-Restore})
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


#Gets the GPO(s) to be operated on. Returns an array of GPOs.
function Get-GPOArray
{
    param 
    (
        [string]$gpoIdentity = "",
        [boolean]$allGPOs = $false
    )
    switch($allGPOs)
    {
        $true
        {
            if($gpoIdentity -eq "")
            {
                try 
                {
                    Write-Host ("Running on all GPOs on the domain.")
                    return Get-GPO -All -ErrorAction Stop 
                }
                catch 
                {
                    Write-Output ("Something went wrong when getting all " +  
                    "GPOs on the domain. Please try again after checking " +
                    "your settings. If this error persists, try preforming " +
                    "actions on GPOs one at a time.`n")
                    exit
                }
            Write-Output ("Running on all GPOs on the domain.")
            }
            else
            {
                Write-Output ("Invalid GPO Selection. Choose either an " +
                "individual GPO or all GPOs.`n")
                exit
            }

            break
        }

        $false
        {
            if($gpoIdentity -match "^[A-Fa-f0-9]+-[A-Fa-f0-9]+-[A-Fa-f0-9]+-"+
            "[A-Fa-f0-9]+-[A-Fa-f0-9]+$")
            {
                try 
                {
                    Write-Host ("Running on GPO: " + $gpoIdentity) 
                    return @(Get-GPO -Guid $gpoIdentity -ErrorAction Stop)
                }
                catch 
                {
                    Write-Output ("Invalid GPO GUID. Check your spelling.")
                    Write-Output ("GUIDs consist of 32 hexadecimal digits " + 
                    "separated by 4 dashes in the format " + 
                    "'xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'.`n")
                    exit
                }
            }
            elseif($gpoIdentity -ne "")
            {
                try 
                {
                    Write-Host ("Running on GPO: " + $gpoIdentity)
                    return Get-GPO -Name $gpoIdentity -ErrorAction Stop
                }
                catch 
                {
                    Write-Output ("Invalid GPO GUID. Check your spelling.")
                    exit
                }
            }
            else 
            {
                Write-Host ("No GPO specified, Please enter a GPO.")
                exit
            }
            break
        }
    }
}


#Gets the path to save output to if provided. Also creates the output folder
function Get-OutputPath
{
    param 
    (
        [string]$output
    )
    $time = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"

    if("" -ne $output -and (Test-Path -Path $output -PathType "Container"))
    {
        try
        {

            $outputPath = New-Item -Path $output -Name ("privAudit-" + $time) `
            -ItemType "Directory" -ErrorAction Stop
            Write-Host ("Outputting backup to " + $outputPath.FullName)
            return ($outputPath.FullName) 
        }
        catch
        {
            Write-Output ("Unable to create output directory. Please check " + 
            "your permissions and try again.")
            exit
        }
    }
    elseif("" -ne $output)
    {
        Write-Output ("Please choose a valid directory for output")
        exit  
    }
    else
    {
        Write-Host ("No output specificed.")
        return ("")    
    }
}


#Gets the path to take input froom if provided. 
function Get-InputPath
{

    param
    (
        [string]$inputDirectory
    )

    if("" -ne $inputDirectory -and (Test-Path -Path $inputDirectory -PathType `
    "Container"))
    {
        $inputPath = (Get-Item $inputDirectory).FullName 
        return $inputPath
    }
    elseif("" -ne $inputDirectory)
    {
        Write-Output ("Please choose a valid directory for input")
        exit          
    }
}


#Performs the privilege audit function of the script
#Print by privielige or by GPO
#Add extra column to output table
#Last modified date
#What 
function Start-Audit
{
    param
    (
        [System.Array]$gpoArray,
        [string]$outputPath = ""
    )

    New-Report -OutputPath $outputPath -ReportType "audit" | Out-Null

    foreach($gpo in $gpoArray)
    {
        $auditResults = ""
        $auditResults += ($gpo.DisplayName + "`n") 

        #--Temp--#
        $auditResults += ("Last modified    : " + $gpo.ModificationTime + "`n")
        $auditResults += ("User version     : " + $gpo.user.DSVersion + "`n")
        $auditResults += ("Computer version : " + $gpo.ComputerVersion + "`n")
        #--Temp--#


        $gpoReport = [XML]$gpo.GenerateReport("XML")
        $rightsAssignment = $gpoReport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment
        if($rightsAssignment -ne $null)
        {
            $auditResults += ("`n")
            foreach($privilege in $rightsAssignment)
            {
                $table = New-Object System.Data.DataTable
                $column0 = New-Object System.Data.DataColumn("GPO", [string])#--Temp--#
                $column1 = New-Object System.Data.DataColumn("Name", [string])
                $column2 = New-Object System.Data.DataColumn("SID", [string])
                $table.Columns.add($column0)#--Temp--#
                $table.Columns.add($column1)
                $table.Columns.add($column2)

                foreach($member in $privilege.Member)
                {
                    $row = $table.NewRow()
                    $row.GPO = ($gpo.DisplayName + " " )#--Temp--#
                    $row.Name = ($member.Name.innerText + " ")
                    $row.SID = ($member.SID.innerText)
                    $table.Rows.Add($row)
                }

                $auditResults += ($privilege.Name)
                $auditResults += (Format-Table -InputObject $table | Out-String)

            }
        }
        else
        {
            $auditResults += ("-"  * $gpo.DisplayName.length + "`n")
            $auditResults += ("No User Rights Assignment policies in " + 
            $gpo.DisplayName) 
            $auditResults += ("`n`n`n")
        }

        Write-Report -outputPath $outputPath -reportType "audit" -reportResults `
        $auditResults

    }
}
#------------------------------------------------------------------------------#

#Performs the GPO backup function of the script
function Start-Backup
{
    param
    (
        [System.Array]$gpoArray,
        [string]$outputPath = ""
    )

    if(New-Report -OutputPath $outputPath -ReportType "backup")
    {
        foreach($gpo in $gpoArray)
        {
            $backupResults = ""

            $backupGpo = Backup-GPO -Guid $gpo.id -Path $outputPath

            $backupResults += ("Display Name  :  " + $backupGpo.DisplayName + 
            "`n")
            $backupResults += ("GUID          :  " + $backupGpo.GpoId + "`n")
            $backupResults += ("Backup ID     :  " + $backupGpo.Id + "`n")
            $backupResults += ("`n")

            Write-Report -outputPath $outputPath -reportType "backup" `
            -reportResults $backupResults
        }
    }
    else
    {
        Write-Output ("A valid output directory is required for the backup " + 
        "function. Please check your permissions.")
        exit
    }
}


#Performs the GPO Restore function of the script
function Start-Restore
{
    param
    (
        [System.Array]$gpoArray,
        [string]$outputPath = "",
        [string]$inputPath
    )

    New-Report -OutputPath $outputPath -ReportType "restore" | Out-Null
    
    foreach($gpo in $gpoArray)
    {
        $restoreResults = ""
        try
        {
        
            $restoredGpo = Restore-GPO -Path $inputPath -GUID $gpo.id `
            -ErrorAction Stop

            $restoreResults += ("Display Name   :  " + $restoredGpo.DisplayName + 
            "`n")
            $restoreResults += ("GUID           :  " + $restoredGpo.Id + "`n")
            $restoreResults += ("Restored from  :  " + $inputPath)
            $restoreResults += ("`n")

        }
        catch [System.ArgumentException]
        {
            $restoreResults += ("Could not restore " + $gpo.DisplayName + ". " + 
            "Please check that the provided path contains backups for all GPOs.")
        }
        catch [System.UnauthorizedAccessException]
        {
            $restoreResults += ("Could not restore " + $gpo.DisplayName + ". " + 
            "Please check your permissions.")
        }
        catch
        {
            $restoreResults += ("Could not restore " + $gpo.DisplayName + ". " +
            "Please check your parameters to make sure they are correct.")
        }
        
        Write-Report -outputPath $outputPath -reportType "restore" `
        -reportResults $restoreResults

    }
}


#Creates the file that the script's report will be put in.
function New-Report
{
    param
    (
        [string]$outputPath,
        [string]$reportType
    )

    if("" -ne $outputPath)
    {
        try
        {
            New-Item -Path $outputPath -Name ($reportType + "Report.txt") `
            -ItemType "File" -ErrorAction Stop | Out-Null
            Write-Host ("Created output file at " + $outputPath)
            return $true
        }
        catch
        {
            Write-Output ("Could not create output file. Please check your " + 
            "permissions and try again.")
            exit
        }
    }
    else 
    {
        return $false
    }
}


#Displays the report generated by the script, either to console or to the given file
function Write-Report
{
    param
    (
        [string]$outputPath,
        [string]$reportType,
        [string]$reportResults
    )

    if("" -eq $outputPath)
    {
        $reportResults = ("`n" + $reportResults)
        Write-Output $reportResults
    }
    else 
    {
        try
        {
            Add-Content -Path ($outputPath + "/" + $reportType + `
            "Report.txt") -Value $reportResults -ErrorAction Stop
        }
        catch
        {
            Write-Output ("Could not output results to file. Please check " +
            "your permissions and try again.")
        }
    }
}


#Main
#------------------------------------------------------------------------------#
$modeFunction = Get-Mode -Audit $audit -Backup $backup -Restore $restore
$gpoArray = Get-GPOArray -GPOIdentity $gpoIdentity -AllGPOs $AllGpos
$outputPath = Get-OutputPath -Output $output
$inputPath = Get-InputPath -Input $inputdirectory


& $modeFunction -gpoArray $gpoArray -outputPath $outputPath -inputPath $inputPath
