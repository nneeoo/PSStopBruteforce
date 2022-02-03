# Get-Bruteforce

The script checks logs and displays statistics and IP addresses of attackers depending on the specified parameters.

``` Powershell
Get-Bruteforce
[-Attempts <UInt16>]
[-Last <UInt16>]
[-Include Anonymous Logon]
```

# Description

List of parameters for **Get-Bruteforce**:

_Attempts_ specifies the number of successful logins to display information about the attacker's ip address.

_Last_ specifies the time period in hours for which the log should be fetched.

__Include Anonymous Logon_ adds successful anonymous network logins to the selection.

## Examples

#### Example 1: information Output
The module displays ip addresses that have had at least one successful login in the last 24 hours

``` Powershell
Get-Bruteforce
````

#### Example 2: Output information with parameters

The module adds outputs

``` Powershell
Get-Bruteforce -Attempts 1 -Last 1 | Format-Table
````
