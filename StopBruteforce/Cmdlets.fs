module StopBruteforce

open System.Management.Automation
open System.Security.Principal
open Miscs

(*
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
*)
[<Cmdlet(VerbsCommon.Get, "Bruteforce")>]
type public GetBruteforce() =
    inherit Cmdlet()
    let mutable attempts = 10
    let mutable last = 24.0

    [<Parameter(Position = 0); ValidateNotNull>]
    member x.Attempts
        with get () = attempts
        and set v = attempts <- v

    [<Parameter(Position = 1); ValidateNotNull>]
    member x.Last
        with get () = last
        and set v = last <- v

    override this.ProcessRecord() =
        match WindowsIdentity.GetCurrent() |> WindowsPrincipal with
        | principal when principal.IsInRole WindowsBuiltInRole.Administrator ->
            EventLog.getFailureAudit last
            |> Array.filter (fun i -> i.Attempts >= attempts)
            |> Array.iter this.WriteObject
        | _ ->
            let exn = exn "To use Protect-FromBruteforce, you need administrator rights"

            this.WriteError(ErrorRecord(exn, "1", ErrorCategory.PermissionDenied, "Get-Bruteforce"))


(*
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
*)
[<Cmdlet(VerbsLifecycle.Stop, "Bruteforce")>]
type public StopBruteforce() =
    inherit Cmdlet()
    let mutable attempts = 10
    let mutable last = 24.0
    let mutable expire = SwitchParameter(false)

    [<Parameter(Position = 0); ValidateNotNull>]
    member x.Attempts
        with get () = attempts
        and set v = attempts <- v

    [<Parameter(Position = 1); ValidateNotNull>]
    member x.Last
        with get () = last
        and set v = last <- v

    [<Parameter>]
    member x.Expire
        with get () = expire
        and set v = expire <- v

    override this.ProcessRecord() =
        match WindowsIdentity.GetCurrent() |> WindowsPrincipal with
        | principal when principal.IsInRole WindowsBuiltInRole.Administrator ->
            let report = EventLog.getFailureAudit last |> Array.filter (fun i -> i.Attempts >= attempts)

            let addresses = report |> Array.map (fun i -> i.IpAddress.ToString())

            match @"Get-NetFirewallRule 'Stop-Bruteforce' | Get-NetFirewallAddressFilter " |> Pwsh.invoke with
            | None ->
                match @"New-NetFirewallRule -Name 'Stop-Bruteforce' -DisplayName 'Stop-Bruteforce' -Action Block -Direction Inbound -Enabled True -RemoteAddress "
                      + (addresses |> String.concat ",")
                      |> Pwsh.invoke with
                | Some _ -> report |> Array.filter (fun i -> i.Attempts >= attempts) |> Array.iter this.WriteObject
                | None ->
                    let exn = exn "Can not create new firewall rule"

                    (ErrorRecord(exn, "1", ErrorCategory.InvalidResult, "Stop-Bruteforce")) |> this.WriteError

            | Some psObjectsOption ->
                let before =
                    [| for p in psObjectsOption do
                           for i in p.Members.["RemoteAddress"].Value :?> string array do
                               yield i |]

                let concat =
                    if this.Expire.IsPresent then
                        addresses
                    else
                        [| before; addresses |] |> Array.concat |> Array.distinct
                    |> String.concat ","

                match @"Set-NetFirewallRule -PassThru -Name 'Stop-Bruteforce' -RemoteAddress " + concat |> Pwsh.invoke with
                | Some _ ->
                    printfn "%s" "New entried was added to Stop-Bruteforce rule"
                    report |> Array.filter (fun i -> i.Attempts >= attempts) |> Array.iter this.WriteObject
                | None ->
                    let exn = exn "Wasn't able to set firewall rule"

                    (ErrorRecord(exn, "1", ErrorCategory.InvalidResult, "Stop-Bruteforce")) |> this.WriteError

        | _ ->
            let exn = exn "To use Protect-FromBruteforce, you need administrator rights"

            this.WriteError(ErrorRecord(exn, "1", ErrorCategory.PermissionDenied, "Stop-Bruteforce"))



(*
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
*)
[<Cmdlet(VerbsSecurity.Protect, "FromBruteforce")>]
type public ProtectFromBruteforce() =
    inherit Cmdlet()
    let mutable attempts = 1
    let mutable last = 48.0
    let mutable rdp: SwitchParameter = SwitchParameter(true)
    let mutable smb: SwitchParameter = SwitchParameter(false)
    let mutable winRM: SwitchParameter = SwitchParameter(false)

    [<Parameter(Position = 0); ValidateNotNull>]
    member x.Attempts
        with get () = attempts
        and set v = attempts <- v

    [<Parameter(Position = 1); ValidateNotNull>]
    member x.Last
        with get () = last
        and set v = last <- v

    [<Parameter>]
    member x.RDP
        with get () = rdp
        and set v = rdp <- v

    [<Parameter>]
    member x.SMB
        with get () = smb
        and set v = smb <- v

    [<Parameter>]
    member x.WinRM
        with get () = winRM
        and set v = winRM <- v

    override this.ProcessRecord() =
        match WindowsIdentity.GetCurrent() |> WindowsPrincipal with
        | principal when principal.IsInRole WindowsBuiltInRole.Administrator ->
            let report = EventLog.getSuccessAudit last

            let addresses = report |> Seq.map (fun i -> i.ToString()) |> String.concat ","

            if rdp.IsPresent then
                match @"Set-NetFirewallRule -PassThru -Name 'RemoteDesktop-UserMode-In-TCP' -RemoteAddress " + addresses
                      |> Pwsh.invoke with
                | Some _ -> printfn "%s" "Standard firewall rule was set for RDP TCP"
                | _ -> ()

                match @"Set-NetFirewallRule -PassThru -Name 'RemoteDesktop-UserMode-In-UDP' -RemoteAddress " + addresses
                      |> Pwsh.invoke with
                | Some _ -> printfn "%s" "Standard firewall rule was set for RDP UDP"
                | _ -> ()

            if smb.IsPresent then
                match @"Set-NetFirewallRule -PassThru -Name 'FPS-SMB-In-TCP' -RemoteAddress " + addresses |> Pwsh.invoke with
                | Some _ -> printfn "%s" "Standard firewall rule was set for SMB"
                | _ -> ()

            if winRM.IsPresent then
                match @"Set-NetFirewallRule -PassThru -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress " + addresses
                      |> Pwsh.invoke with
                | Some _ -> printfn "%s" "Standard firewall rule was set for WINRM"
                | _ -> ()

            report |> Array.iter this.WriteObject

        | _ ->
            let exn = exn "To use Protect-FromBruteforce, you need administrator rights"

            this.WriteError(ErrorRecord(exn, "1", ErrorCategory.PermissionDenied, "Protect-FromBruteforce"))

[<Cmdlet(VerbsSecurity.Unprotect, "FromBruteforce")>]
type public UnprotectFromBruteforce() =
    inherit Cmdlet()
    let mutable rdp = SwitchParameter(true)
    let mutable smb = SwitchParameter(false)
    let mutable winRM = SwitchParameter(false)

    [<Parameter>]
    member x.RDP
        with get () = rdp
        and set v = rdp <- v

    [<Parameter>]
    member x.SMB
        with get () = smb
        and set v = smb <- v

    [<Parameter>]
    member x.WinRM
        with get () = winRM
        and set v = winRM <- v

    override this.ProcessRecord() =
        match WindowsIdentity.GetCurrent() |> WindowsPrincipal with
        | principal when principal.IsInRole WindowsBuiltInRole.Administrator ->
            if rdp.IsPresent then
                match @"Set-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP' -RemoteAddress ANY" |> Pwsh.invoke with
                | Some _ -> printfn "%s" "Standard firewall rule was reset for RDP TCP"
                | _ -> ()

                match @"Set-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-UDP' -RemoteAddress ANY" |> Pwsh.invoke with
                | Some _ -> printfn "%s" "Standard firewall rule was reset for RDP UDP"
                | _ -> ()

            if smb.IsPresent then
                match @"Set-NetFirewallRule -Name 'FPS-SMB-In-TCP' -RemoteAddress ANY" |> Pwsh.invoke with
                | Some _ -> printfn "%s" "Standard firewall rule was reset for SMB"
                | _ -> ()

            if winRM.IsPresent then
                match @"Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress ANY" |> Pwsh.invoke with
                | Some _ -> printfn "%s" "Standard firewall rule was reset for WINRM"
                | _ -> ()
        | _ ->
            let exn = exn "To use Protect-FromBruteforce, you need administrator rights"

            this.WriteError(ErrorRecord(exn, "1", ErrorCategory.PermissionDenied, "Protect-FromBruteforce"))