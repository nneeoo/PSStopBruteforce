# # Unprotect-FromBruteforce

The module resets the Remote Address settings for standard firewall rules.

``` Powershell
Unprotect-FromBruteforce 
[-SMB]
[-RDP]
[-WinRM]
[-What If]
```

# Description

List of parameters for **Unprotect-FromBruteforce**:

_SMB_ sets RemoteAddress back to ANY for the standard rule for SMB.

_RDP_ sets RemoteAddress back to ANY in the standard remote desktop rules.

_WinRM_ sets the Remote Address back to ANY standard rules of WinRM.

_Whatif_ shows the result of execution without creating or changing firewall rules.

## Examples

#### Example 1: Resetting RDP rules
The script will reset the RemoteAddress area of the firewall remote desktop rule back to ANY.

``` Powershell
Unprotect-FromBruteforce -RDP
````
