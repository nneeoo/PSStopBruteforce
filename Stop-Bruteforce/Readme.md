# Stop-Bruteforce

The script checks the logs and blocks the ip address depending on the specified parameters.

``` Powershell
Stop-Bruteforce
[-Attemts <uint16>]
[-Last <uint16>]
[-Expire]
[-BlockAnonimousLogon]
[-WhatIf]

```

# Description

List of parameters for **Stop-Bruteforce**:

* Attempts
* Last
* Expire
* BlockAnonimousLogon
* WhatIf

_Attempts_ selects by the number of failed login attempts specified in the parameter.

_Last_ specifies the time period in hours for which the log should be fetched.

_Expire_ removes all previously entered ip addresses from the "Stop-Bruteforce" firewall rule.

_BlockAnonimousLogon_ gets successful anonymous network login attempts, does not take into account the _attempts_ parameter.

_Whatif_ shows the result of execution without creating or changing firewall rules.

## Examples

#### Example 1: blocking attackers
Skrit will block all ip addresses that have made a mistake in entering a username or password 10 times in the last hour.

``` Powershell
Stop-Bruteforce -Attempts 10 -Last 1
````

#### Example 2: Blocking attackers with clearing firewall rules

Skrit blocks all ip addresses that have made a mistake in entering a username or password 10 times in the last hour and clears the list of previously blocked IP addresses.

``` Powershell
Stop-Bruteforce -Attempts 10 -Last 1 -Expire
````
