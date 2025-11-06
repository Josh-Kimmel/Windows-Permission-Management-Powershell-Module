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
    
.PARAMETER GPOIdentity
    Parameter that specifies the identity of specific GPOs to be operated on.
    Aliased to -g or -gpo
    This parameter can be either either be given as a GPOs' names and/or GUIDs.
    Overridden by the AllGPOs parameter.

.PARAMETER AllGPOs
    Flag that specifices that all GPOs on a domain are going to be operated on.
    Aliased to -a or -all
    Overrides the GPOIdentity parameter.

.PARAMETER Output
    Parameter that specifies the directory for Get-PrivilegeAudit to place its output.
    Aliased to -o or -out
    The output will be a csv named "PrivilegeAudit-yyyy-MM-dd-HH-mm-ss.csv".
    The output files vary depending on the mode. 

.EXAMPLE
    C:\PS>Get-PrivilegeAudit -GPOIdentity "Default Domain Policy"

    Description:
    Returns a privilege audit of the "Defaut Domain Policy" GPO

.EXAMPLE
    C:\PS>Get-PrivilegeAudit -AllGPOs -Output "C:\"

    Description:
    Writes a privilege audit of all GPOs on a domain to a .CSV file in the "C:\" directory.

.EXAMPLE
    C:\PS>Get-PrivilegeAudit -Backup -GPOIdentity "Default Domain Policy" -Output "."

    Description:
    Creates a backup of the "Default Domain Policy" in a folder in the current directory.
    
.EXAMPLE
    C:\PS>Get-PrivilegeAudit -Restore -AllGPOs -InputDirectory "C:\privAudit-yyyy-MM-dd-HH-mm-ss"

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
    [Alias("gpo", "g")]
    [System.Array]$GPOIdentity,
    #An array of the GPOs to be acted on. Can be either its name or GUID.

    [Alias("all", "a")]
    [switch]$AllGPOs = $false,
    #Act on all GPOs in the domain

    [Alias("out", "o")]
    [string]$Output
)


#Gets the GPO(s) to be operated on. Returns an array of GPOs.
function Get-GPOArray
{
    param 
    (
        [System.Array]$gpoIdentityArray,
        [boolean]$allGPOs
    )
    
    $gpoArray = @()

    if($allGPOs)
    {
        $gpoArray = Get-GPO -All 
    }
    else
    {
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
    }

    Write-Host ("Operating on " + $gpoArray.Length + " GPOs")
    return $gpoArray
}


#Gets the path to save output to if provided. Also creates the output folder
function Get-OutputPath
{
    param 
    (
        [string]$output
    )


    if(($null -ne $output) -and (Test-Path -Path $output))
    {
        $fullOutputPath = (Get-Item $output).FullName

        $time = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"

        $fullOutputPath += ("\PrivilegeAudit-" + $time + ".csv")

        Write-Host ("Outputting to " + $fullOutputPath)
        return $fullOutputPath
    }
    elseif("" -ne $output)
    {
        Write-Host ("Invalid output path. Outputting to screen.")
        return $null
    }
    else
    {
        return $null
    }
}



#Performs the privilege audit function of the script
function Start-Audit
{
    param
    (
        [System.Array]$gpoArray
    )

    $table = New-Object System.Data.DataTable
    
    $column1 = New-Object System.Data.DataColumn("Domain", [string])
    $column2 = New-Object System.Data.DataColumn("GPO", [string])
    $column3 = New-Object System.Data.DataColumn("Privilege", [string])
    $column4 = New-Object System.Data.DataColumn("Name", [string])
    $column5 = New-Object System.Data.DataColumn("SID", [string])
    $table.Columns.add($column1)
    $table.Columns.add($column2)
    $table.Columns.add($column3)
    $table.Columns.add($column4)
    $table.Columns.add($column5)

    
    foreach($gpo in $gpoArray)
    {
        $gpoReport = [XML]$gpo.GenerateReport("XML")
        $rightsAssignment = `
        $gpoReport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment

        $gpoDomain = $gpo.DomainName
        $gpoName = $gpo.DisplayName
        
        if($null -ne $rightsAssignment)
        {
            foreach($privilege in $rightsAssignment)
            {
                $privilegeName = $privilege.Name
                
                foreach($member in $privilege.Member)
                {
                    $memberName = $member.Name.innerText
                    $memberSID = $member.SID.innerText

                    $row = $table.NewRow()
                    $row.Domain = $gpoDomain
                    $row.GPO = $gpoName
                    $row.Privilege = $privilegeName
                    $row.Name = $memberName
                    $row.SID = $memberSID
                    $table.Rows.add($row)
                    #Write-Host $row.ItemArray
                }
            }
        }
    }

    return $table
}


#Main
#------------------------------------------------------------------------------#
$gpoArray = Get-GPOArray -GPOIdentity $gpoIdentity -AllGPOs $AllGpos
$outputPath = Get-OutputPath -output $output


$auditTable = Start-Audit -gpoArray $gpoArray -outputPath $outputPath


if($null -ne $outputPath)
{
    $auditTable | Export-Csv -Path $outputPath -NoTypeInformation
}
else
{
    Write-Output $auditTable | Format-Table
}
