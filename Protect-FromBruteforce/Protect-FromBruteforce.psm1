<#
        .SYNOPSIS
        Add ip adresses from successfull network logins to firewall.

        .DESCRIPTION
        Read Windows Event Log, search for Audit Seccess.
        Adds ip adresses of non anonimous users to default firewall rules.

        .EXAMPLE
        #Add IP adresses into remote desktop.
        Protect-FromBruteforce -rdp

        .EXAMPLE
        #Get objects which will be added to firewall without adding them.
        Protect-FromBruteforce

        .INPUTS
        None. 

        .OUTPUTS
        System.Array. Returns array of [Report] objects.
#>
function Protect-FromBruteforce {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param (
        [Parameter(Mandatory = $false,
            HelpMessage = "Allow ip addresses that logined in system for last N hours")]
        [ValidateNotNullOrEmpty()]
        [UInt16]$Last = 24,

        [Parameter(Mandatory = $false,
            HelpMessage = "How many logins need to allow IP adress")]
        [UInt16]$Attempts = 1,

        [Parameter(Mandatory = $false,
            HelpMessage = "Add successfull logined IP addresses to remote scope of standard RDP rule.")]
        [switch]$RDP,

        [Parameter(Mandatory = $false,
            HelpMessage = "Add successfull logined IP addresses to remote scope of standard SMB rule.")]
        [switch]$SMB,
        
        [Parameter(Mandatory = $false,
            HelpMessage = "Add successfull logined IP addresses to remote scope of standard WinRM rule.")]
        [switch]$WinRM
    )
    begin {
        class Report {
            [string]$IpAddress
            [string]$HostName
            [string]$Workstation
        }
        
        #Region Locale
        $PathToModule = Split-Path (Get-Module -ListAvailable Protect-FromBruteforce).path

        if ((Get-WinSystemLocale).Name -eq "ru-RU") {
            $Locale = Import-Clixml $PathToModule\ru-RU.xml 
        }
        else {
            $Locale = Import-Clixml $PathToModule\en-US.xml 
        }
        #EndRegion Locale

        $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($false -eq $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Error $Locale.ErrorRights
            break
        }

        #Check if parameters not null
        if ($false -eq $SMB -and $false -eq $WinRM -and $false -eq $RDP) {
            Write-Error $Locale.ErrorParam
            break
        }
    }
    process {
        #Getting date -one hour (default)
        $DateTime = [DateTime]::Now.AddHours(-$Last)

        #Region CollectEvents
        Write-Verbose $locale.ReadingLog

        $SuccessEvents = ([System.Diagnostics.EventLog]::GetEventLogs($env:COMPUTERName) | 
            Where-Object -Property Log -EQ "Security").Entries | 
        Where-Object EntryType -EQ "SuccessAudit" | 
        Where-Object TimeWritten -GE $DateTime | 
        Where-Object InstanceID -EQ 4624 | 
        Select-Object @{n = 'Workstation'; e = { $_.ReplacementStrings[-16] } }, 
        @{n = 'IpAddress'; e = { $_.ReplacementStrings[18] } }, 
        @{n = 'LogonType'; e = { $_.ReplacementStrings[8] } },
        @{n = 'AccountName'; e = { $_.ReplacementStrings[5] } } | 
        Where-Object Logontype -EQ 3 | Where-Object Logontype -EQ 3 | 
        Where-Object AccountName -NE "ANONYMOUS LOGON"

        $UserIPs = $SuccessEvents | Group-Object -Property IpAddress | Sort-Object Count | Where-Object Name -NotLike '-' | Where-Object Count -GE $Attempts 
        #EndRegion CollectEvents

        New-Variable -Name OutputArray -Value @() -WhatIf:$false
  
        $UserIPs | ForEach-Object {
            $Report = [Report]::new()
            $Report.IpAddress = $_.Name
            $Report.HostName = ([System.Net.Dns]::Resolve($_.Name)).Hostname
            $Report.Workstation = ($_.Group | Group-Object Workstation).Name
            $OutputArray += $Report
        }
    }
    end {
        #Region RDP
        if ($RDP) {
            
            $RuleDisplayName = (Get-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP" -ErrorAction SilentlyContinue).DisplayName
  
            if ($null -eq $RuleDisplayName) {
                if ($null -eq $UserIPs) {
                    Write-Error $Local  
                    break
                }
            }
            else {
                $RDPTCP = (Get-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP" -ErrorAction SilentlyContinue).DisplayName
                $RDPUDP = (Get-NetFirewallRule -Name "RemoteDesktop-UserMode-In-UDP" -ErrorAction SilentlyContinue).DisplayName
                $Verb = $Locale.SetRule + " ( " + $RDPTCP + " ) " + "( " + $RDPUDP + " )"

                if ($PSCmdlet.ShouldProcess($Verb, $BlockList.IpAddress, 'Protect-FromBruteforce')) {
                    Write-Verbose $Verb
                    Set-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP" -RemoteAddress $OutputArray.IpAddress.IPAddressToString
                    Set-NetFirewallRule -Name "RemoteDesktop-UserMode-In-UDP" -RemoteAddress $OutputArray.IpAddress.IPAddressToString
                }
                
            }
        }
        #EndRegion RDP

        #Region SMB
        if ($SMB) {
            $RuleDisplayName = (Get-NetFirewallRule -Name "FPS-SMB-In-TCP" -ErrorAction SilentlyContinue).DisplayName
            if ($null -eq $RuleDisplayName) {
                if ($null -eq $UserIPs) {
                    Write-Error $Locale.ErrorSMB
                    break
                }
            }
            else {
                $Verb = $Locale.SetRule + " ( " + $RuleDisplayName + " )"
                if ($PSCmdlet.ShouldProcess($Verb, $BlockList.IpAddress, 'Protect-FromBruteforce')) {
                    Write-Verbose $Verb

                    Set-NetFirewallRule -Name "FPS-SMB-In-TCP" -RemoteAddress $OutputArray.IpAddress.IPAddressToString
                }
               
            }
        }
        #EndRegion SMB

        #Region WinRM
        if ($WinRM) {
            $RuleDisplayName = (Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -ErrorAction SilentlyContinue).DisplayName
            if ($null -eq $RuleDisplayName) {
                if ($null -eq $UserIPs) {
                    Write-Error $Locale.ErrorWinRm
                    break
                }
            }
            else {
                $Verb = $Locale.SetRule + " ( " + $RuleDisplayName + " )"
                if ($PSCmdlet.ShouldProcess($Verb, $BlockList.IpAddress, 'Protect-FromBruteforce')) {

                    $Verb = $Locale.SetRule + " ( " + $RuleDisplayName + " )"
                    Write-Verbose $Verb
                    
                    Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress $OutputArray.IpAddress.IPAddressToString
                }
            }
        }
        #EndRegion WinRM

        return $OutputArray
    }
}
#Example usage: 
#Protect-FromBruteforce -RDP -WhatIf