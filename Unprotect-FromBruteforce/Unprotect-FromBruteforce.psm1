<#
        .SYNOPSIS
        Reset remote scope of firewall rules back to ANY.

        .DESCRIPTION
        Reset remote scope of firewall rules back to ANY.

        .EXAMPLE
        #Reset default RDP rules to ANY.
        Unprotect-FromBruteforce -RDP

        .INPUTS
        None. 

        .OUTPUTS
        None.
#>
function Unprotect-FromBruteforce {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    param (
        [Parameter(Mandatory = $false,
            HelpMessage = "Reset remote address scope of standard RDP firewall rules to ANY.")]
        [switch]$RDP,
        [Parameter(Mandatory = $false,
            HelpMessage = "Reset remote address scope of standard SMB firewall rule to ANY.")]
        [switch]$SMB,
        [Parameter(Mandatory = $false,
            HelpMessage = "Reset remote address scope of standard WinRM firewall rule to ANY.")]
        [switch]$WinRM
    )

    begin {
        #Find path to this module folder
        $PathToModule = Split-Path (Get-Module -ListAvailable Unprotect-FromBruteforce).path

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

        #Check if parameters not null
        if ($false -eq $SMB -and $false -eq $WinRM -and $false -eq $RDP) {
            Write-Error $Locale.ErrorParam
            break
        }
    }
    
    process {
        #Region RDP
        if ($RDP) {

            $RDPTCP = (Get-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP" -ErrorAction SilentlyContinue).DisplayName
            $RDPUDP = (Get-NetFirewallRule -Name "RemoteDesktop-UserMode-In-UDP" -ErrorAction SilentlyContinue).DisplayName
            $Verb = $Locale.RDP + " ( " + $RDPTCP + " ) " + "( " + $RDPUDP + " )"

            if ($PSCmdlet.ShouldProcess($Verb, $BlockList.IpAddress, 'Unprotect-FromBruteforce')) {
                Write-Verbose $Verb

                Set-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP" -RemoteAddress ANY
                Set-NetFirewallRule -Name "RemoteDesktop-UserMode-In-UDP" -RemoteAddress ANY
            }  
        }
        #EndRegion RDP

        #Region SMB
        if ($SMB) {
    
            $RuleDisplayName = (Get-NetFirewallRule -Name "FPS-SMB-In-TCP" -ErrorAction SilentlyContinue).DisplayName    
            $Verb = $Locale.SMB + " ( " + $RuleDisplayName + " )"

            if ($PSCmdlet.ShouldProcess($Verb, $BlockList.IpAddress, 'Unprotect-FromBruteforce')) {
                Write-Verbose $Verb
                Set-NetFirewallRule -Name "FPS-SMB-In-TCP" -RemoteAddress ANY
            }
        }
        #EndRegion SMB

        #Region WinRM
        if ($WinRM) {
            
            $RuleDisplayName = (Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -ErrorAction SilentlyContinue).DisplayName
            $Verb = $Locale.WinRm + " ( " + $RuleDisplayName + " )"
          
            if ($PSCmdlet.ShouldProcess($Verb, $BlockList.IpAddress, 'Unprotect-FromBruteforce')) {
                Write-Verbose $Verb
                Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP-PUBLIC" -RemoteAddress ANY
            }        
        }
        #EndRegion WinRM
    }    
}
#Example usage: 
#Unprotect-FromBruteforce -RDP -Verbose