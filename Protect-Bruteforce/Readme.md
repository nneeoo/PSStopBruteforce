# Protect-Bruteforce

The script checks the logs and adds the ip address to the firewall rule depending on the specified parameters.

``` Powershell
Protect-Bruteforce
[-Attemts <UInt16>]
[-Last <UInt16>]
[-SMB]
[-RDP]
[-WinRM]
[-WhatIf]
```

# Description

List of parameters for **Protect-Bruteforce**:

* Attempts
* Last
* SMB
* *RDP
* WinRM
* WhatIf

_Attempts_ specifies the number of successful logins to add an IP address to the whitelist.

_Last_ specifies the time period in hours for which the log should be fetched.

_SMB_ adds IP addresses from the log in the specified selection to the standard SMB rules.

_RDP_ adds IP addresses from the log in the specified selection to the standard remote desktop rules.

_WinRM_ adds IP addresses from the log in the specified selection to the standard WinRM rules.

_Whatif_ shows the result of execution without creating or changing firewall rules.

## Examples

#### Example 1: information Output

The module displays ip addresses that have had at least one successful login in the last 24 hours

``` Powershell
Protect-Bruteforce
```

#### Example 2: Output information with parameters

The module adds outputs
"'Powershell
Protect-Bruteforce -Attempts 1 -Last 1
`

``` 

#### Example 3: RDP, SMB, and WinRM Protection

The module adds ip addresses with at least one successful login in the last 24 hours to the standard rules of the remote desktop firewall, SMB, and WinRM.
```Powershell
Protect-Bruteforce -RDP -SMB -WinRM
````
