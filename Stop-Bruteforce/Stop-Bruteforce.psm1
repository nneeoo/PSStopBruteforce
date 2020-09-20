<#
        .SYNOPSIS
        Block RDP and SMB bruteforce attacks.

        .DESCRIPTION
        Read Windows Event Log, search for Audit Failure.
        Adds ip adresses of attackers to deny firewall rule.

         .EXAMPLE
        #Block attackers ip adresses with default params.
        Stop-Bruteforce

        .INPUTS
        None. 

        .OUTPUTS
        System.Array. Returns array of [Report] objects.

#>
function Stop-Bruteforce {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
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
            HelpMessage = "Wipe old firewall rule ip adress list")]
        [switch]$Expire,

        [Parameter(Mandatory = $false,
            HelpMessage = "Get ip address of successful anonymous logon, despite of number of attempts")]
        [switch]$BlockAnonimousLogon
    )   

    begin {
        class Report {
            [uint16]$Attempts
            [ipaddress]$IpAddress
            [string]$HostName
        }
        
        #Find path to this module folder
        $PathToModule = Split-Path (Get-Module -ListAvailable Stop-Bruteforce).path

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
    }
    process {
        Write-Verbose $Locale.ReadingLog

        $DateTime = [DateTime]::Now.AddHours(-$Last)

        #Get failed network logons
        $TotalEvents = ([System.Diagnostics.EventLog]::GetEventLogs($env:COMPUTERName) | 
            Where-Object -Property Log -EQ "Security").Entries | 
        Where-Object TimeWritten -GE $DateTime | 
        Where-Object InstanceID -EQ 4625 | 
        Select-Object @{n = 'IpAddress'; e = { $_.ReplacementStrings[-2] } }

        [array]$TopAttackers = @()
        $TopAttackers = $TotalEvents | Group-Object -Property IpAddress | Sort-Object Count | Where-Object Count -GE $Attempts 
    
        #Get NULL LOGON attacks
        if ($BlockAnonimousLogon) {
            $AnonimousLogons = ([System.Diagnostics.EventLog]::GetEventLogs($env:COMPUTERName) | 
                Where-Object -Property Log -EQ "Security").Entries | 
            Where-Object EntryType -EQ "SuccessAudit" | 
            Where-Object TimeWritten -GE $DateTime | 
            Where-Object InstanceID -EQ 4624 | 
            Select-Object @{n = 'IpAddress'; e = { $_.ReplacementStrings[18] } }, 
            @{n = 'LogonType'; e = { $_.ReplacementStrings[8] } },
            @{n = 'AccountName'; e = { $_.ReplacementStrings[5] } } | 
            Where-Object Logontype -EQ 3 | Where-Object Logontype -EQ 3 | 
            Where-Object AccountName -EQ "ANONYMOUS LOGON" | 
            Group-Object -Property IpAddress | Sort-Object Count | Where-Object Name -NotLike '-'

            $TopAttackers += $AnonimousLogons
            $TopAttackers = $TopAttackers | Sort-Object Count
        }

        $GetAttackers = $TopAttackers | Select-Object -Property Name
   

        Write-Verbose ($Locale.UniqueIP + $GetAttackers.Length)
        Write-Verbose ($Locale.TotalAttempts + $TotalEvents.Length)
    
        #Create new array of NULL LOGON ip adresses and failed network logons
        New-Variable -Name OutputArray -WhatIf:$false
        
        foreach ($i in $TopAttackers ) {
            $Report = [Report]::new()
            $Report.Attempts = $i.Count
            $Report.IpAddress = [System.Net.IPAddress]::Parse($i.Name)
            $Report.HostName = ([System.Net.Dns]::Resolve($i.Name)).Hostname
            [array]$OutputArray += $Report
        }

        $OutputArray | Format-Table

        New-Variable -Name Blocklist -WhatIf:$false -Value @()
        
        $OutputArray | ForEach-Object {
            $BlockList += $_
        }
       
    }
    end {
        #Check is Stop-Bruteforce rule already exists
        $RuleDisplayName = (Get-NetFirewallRule -Name "Stop-Bruteforce" -ErrorAction SilentlyContinue).DisplayName
        
        #Check if Expire switch is selected
        if ($Expire) {
            $AlreadyInBlocklist = Get-NetFirewallRule -Name "Stop-Bruteforce" | Get-NetFirewallAddressFilter 
            $BlockList += $AlreadyInBlocklist.RemoteAddress
        }

        #Add new rule or change existing
        if ($null -eq $RuleDisplayName) {
            if ($null -eq $TopAttackers) {
                $Report = [Report]::new()
                $Report.IpAddress = [System.Net.IPAddress]::Parse("0.0.0.1")
                $BlockList += $Report
            }

            if ($PSCmdlet.ShouldProcess($Locale.NewRule, $BlockList.IpAddress, 'Stop-Bruteforce')) {
                Write-Verbose $Locale.NewRule
                New-NetFirewallRule -Name "Stop-Bruteforce" -DisplayName "Stop-Bruteforce" -Action Block -Direction Inbound -Enabled True -RemoteAddress $BlockList.IpAddress -WhatIf:$WhatIfPreference
            }
        }
        else {
            if ($PSCmdlet.ShouldProcess($Locale.SetRule + " ( " + $RuleDisplayName + " )", $BlockList.IpAddress, 'Stop-Bruteforce')) {
                Write-Verbose ($Locale.SetRule + " ( " + $RuleDisplayName + " )")
                Set-NetFirewallRule -Name "Stop-Bruteforce" -RemoteAddress $BlockList.IpAddress -WhatIf:$WhatIfPreference
            }
        }
      
    }
}
#Example use
#Stop-Bruteforce -Attempts 10 -Last 10 -Verbose -WhatIf