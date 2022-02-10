# PSStopBruteforce
![headimg](Assets/Head.png "ExampleUsage")

The **PSStopBruteforce** modules to stop bruteforce attack on SMB, RDP and WinRm.


## Installation

```
Install-Module -Name StopBruteforce
```

## Requirements

The implementation of the module depends on the Windows event log, so the functionality is different for different versions of Microsoft Windows.

| Command                                                                                               | Requirement                      |
|-------------------------------------------------------------------------------------------------------|----------------------------------|
| [Stop-Bruteforce](https://github.com/nneeoo/PSStopBruteforce/wiki/Stop-Bruteforce)                    | Windows Server 2016 or later.    |
| [Get-Bruteforce](https://github.com/nneeoo/PSStopBruteforce/wiki/Get-Bruteforce)                      | Windows Server 2016 or later.           |
| [Protect-FromBruteforce](https://github.com/nneeoo/PSStopBruteforce/wiki/Protect-FromBruteforce)      | Windows Server 2012 R2 or later. |
| [Unprotect-FromBruteforce](https://github.com/nneeoo/PSStopBruteforce/wiki/Unprotect-FromBruteforce)  | Windows Server 2012 R2 or later. |

## Change log

A full list of changes in each version can be found in the [change log](CHANGELOG.md).
