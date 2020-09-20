<#
        .SYNOPSIS
        Get audit failure bruteforce attacks.

        .DESCRIPTION
        Read Windows Event Log, search for Audit Failure and Audit success anonimous logon.
        Return array of BruteStatistics.

         .EXAMPLE
        Get-Bruteforce | Format-Table

        .INPUTS
        None. 

        .OUTPUTS
        System.Array. Returns array of [BruteStatistics] objects.
#>
function  Get-Bruteforce {
    param (
        [Parameter(Mandatory = $false,
            HelpMessage = "Get samples for last N hours")]
        [ValidateNotNullOrEmpty()]
        [UInt16]$Last = 24,

        [Parameter(Mandatory = $false,
            HelpMessage = "How many Attempts need to block IP")]
        [ValidateNotNullOrEmpty()]
        [UInt16]$Attempts = 10,

        [Parameter(Mandatory = $false,
            HelpMessage = "Get ip address of successful anonymous logon, despite of number of attempts")]
        [switch]$IncludeAnonimousLogon
    )   
    begin {
        class BruteStatistics {
            [uint16]$Index
            [uint16]$Attempts
            [ipaddress]$IpAddress
            [array]$UserNames
            [string]$PTR
            [datetime]$ReportDate
        }

        #Find path to this module folder
        $PathToModule = Split-Path (Get-Module -ListAvailable Get-Bruteforce).path

        #Find appropriate localization
        if ((Get-WinSystemLocale).Name -eq "ru-RU") {
            $Locale = Import-Clixml $PathToModule\ru-RU.xml 
        }
        else {
            $Locale = Import-Clixml $PathToModule\en-US.xml 
        }
       
        #Check for administrator privileges
        $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($false -eq $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Error $Locale.ErrorRights
            break
        }

        #Getting date -one hour (default)
        $DateTime = [DateTime]::Now.AddHours(-$Last)
    }
    process {
        $Log = ([System.Diagnostics.EventLog]::GetEventLogs($env:COMPUTERNAME) | 
            Where-Object -Property Log -EQ "Security").Entries 

        #Get failed network logons
        $TotalEvents = $Log | Where-Object InstanceID -EQ 4625 | 
        Where-Object TimeWritten -GE $DateTime | 
        Select-Object @{n = 'IpAddress'; e = { $_.ReplacementStrings[-2] } }, 
        @{n = 'Username'; e = { $_.ReplacementStrings[5] } } | 
        Group-Object -Property IpAddress | Where-Object Count -GE $Attempts

        #Get NULL LOGON attacks
        if ($IncludeAnonimousLogon) {
            $AnonimousLogons = $Log | Where-Object EntryType -EQ "SuccessAudit" | 
            Where-Object TimeWritten -GE $DateTime | 
            Where-Object InstanceID -EQ 4624 |
            Select-Object @{n = 'IpAddress'; e = { $_.ReplacementStrings[18] } }, 
            @{n = 'LogonType'; e = { $_.ReplacementStrings[8] } },
            @{n = 'Username'; e = { $_.ReplacementStrings[5] } } | 
            Where-Object LogonType -EQ 3 |
            Where-Object Username -EQ "ANONYMOUS LOGON" | 
            Group-Object -Property IpAddress | 
            Where-Object Name -NotLike '-'

            $TotalEvents += $AnonimousLogons
        }
    }
    end {
        #Build array for statistics and return that array
        [array]$TopAttackers = @()
        $TopAttackers = $TotalEvents | Sort-Object Count
        
        foreach ($i in $TopAttackers ) {        
            $Entry = [BruteStatistics]::new()
            $Entry.Index = $TopAttackers.indexof($i)
            $Entry.Attempts = $i.Count
            $Entry.IpAddress = [System.Net.IPAddress]::Parse($i.Name)
            $Entry.UserNames = $i.Group.Username | Select-Object -Unique

            [string]$PTR = ([System.Net.Dns]::Resolve($Entry.IpAddress)).Hostname
            if ($PTR -eq $Entry.IpAddress) {
                $Entry.PTR = "None"
            }
            else {
                $Entry.PTR = $PTR
            }
    
            $Entry.ReportDate = Get-Date
            [array]$Attackers += $Entry         
        }
    
        return $Attackers
    }    
}
#Example use
#Get-Bruteforce -IncludeAnonimousLogon