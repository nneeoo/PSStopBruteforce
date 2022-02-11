module StopBruteforce

open System.Management.Automation
open System.Security.Principal
open Miscs

(*
        .SYNOPSIS
        Get audit failure bruteforce attacks.

        .DESCRIPTION
        Read Windows Event Log, search for Audit Failure and Audit success anonymous logon.
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

    [<Parameter(Position = 0); ValidateRange(1, 65535)>]
    member x.Attempts
        with get () = attempts
        and set v = attempts <- v

    [<Parameter(Position = 1); ValidateRange(1, 65535)>]
    member x.Last
        with get () = last
        and set v = last <- v

    override this.ProcessRecord() =
        match WindowsIdentity.GetCurrent() |> WindowsPrincipal with
        | principal when principal.IsInRole WindowsBuiltInRole.Administrator ->
            EventLog.getFailureAudit this.Last
            |> Array.filter (fun i -> i.Attempts >= this.Attempts)
            |> Array.iter this.WriteObject
        | _ -> Err.permissionDenied "Get-Bruteforce" |> this.WriteError


(*
        .SYNOPSIS
        Block RDP and SMB bruteforce attacks.

        .DESCRIPTION
        Read Windows Event Log, search for Audit Failure.
        Adds ip addresses of attackers to deny firewall rule.

        .EXAMPLE
        #Block attackers ip addresses with default params.
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

    [<Parameter(Position = 0); ValidateRange(1, 65535)>]
    member x.Attempts
        with get () = attempts
        and set v = attempts <- v

    [<Parameter(Position = 1); ValidateRange(1, 65535)>]
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
            let report = EventLog.getFailureAudit this.Last |> Array.filter (fun i -> i.Attempts >= this.Attempts)

            let addresses = report |> Array.map (fun i -> i.IpAddress.ToString())

            match @"Get-NetFirewallRule 'Stop-Bruteforce' | Get-NetFirewallAddressFilter " |> Pwsh.invoke, addresses with
            | None, addresses when addresses <> [||] ->
                match NewRule.Sbf + (addresses |> String.concat ",") |> Pwsh.invoke with
                | Some _ -> report |> Array.filter (fun i -> i.Attempts >= this.Attempts) |> Array.iter this.WriteObject
                | None -> Err.newRule "Stop-Bruteforce" |> this.WriteError

            | Some psObjects, addresses ->
                let before =
                    match psObjects :> PSObject seq |> Seq.tryHead, this.Expire.IsPresent with
                    | Some p, false -> p.Members.["RemoteAddress"].Value :?> string array
                    | _ -> Array.empty

                let concat = [| before; addresses |] |> Array.concat |> Array.distinct |> String.concat ","

                match SetRule.Sbf + concat |> Pwsh.invoke with
                | Some _ -> report |> Array.filter (fun i -> i.Attempts >= this.Attempts) |> Array.iter this.WriteObject
                | None -> Err.newRule "Stop-Bruteforce" |> this.WriteError

            | _ -> this.WriteWarning "No failed network logons was detected. Cmdlet did nothing."

        | _ -> Err.permissionDenied "Stop-Bruteforce" |> this.WriteError


(*
        .SYNOPSIS
        Add ip addresses from successful network logins to firewall.

        .DESCRIPTION
        Read Windows Event Log, search for Audit Success.
        Adds ip addresses of non anonymous users to default firewall rules.

        .EXAMPLE
        #Add IP addresses into remote desktop.
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

    [<Parameter(Position = 0); ValidateRange(1, 65535)>]
    member x.Attempts
        with get () = attempts
        and set v = attempts <- v

    [<Parameter(Position = 1); ValidateRange(1, 65535)>]
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
            match EventLog.getSuccessAudit this.Last |> Array.groupBy id with
            | report when report <> [||] ->
                let addresses =
                    report
                    |> Array.filter (fun (_, y) -> y.Length >= this.Attempts)
                    |> Array.map (fun (x, _) -> x.ToString())
                    |> String.concat ","

                if this.RDP.IsPresent then
                    match SetRule.RDP_TCP + addresses |> Pwsh.invoke with
                    | Some _ -> this.WriteVerbose "Standard firewall rule was set for RDP TCP"
                    | _ -> this.WriteWarning "RemoteDesktop-UserMode-In-TCP rule was not found"

                    match SetRule.RDP_UDP + addresses |> Pwsh.invoke with
                    | Some _ -> this.WriteVerbose "Standard firewall rule was set for RDP UDP"
                    | _ -> this.WriteWarning "RemoteDesktop-UserMode-In-UDP rule was not found"

                if this.SMB.IsPresent then
                    match SetRule.SMB + addresses |> Pwsh.invoke with
                    | Some _ -> this.WriteVerbose "Standard firewall rule was set for SMB"
                    | _ -> this.WriteWarning "FPS-SMB-In-TCP rule was not found"

                if this.WinRM.IsPresent then
                    match SetRule.WINRM + addresses |> Pwsh.invoke with
                    | Some _ -> this.WriteVerbose "Standard firewall rule was set for WINRM"
                    | _ -> this.WriteWarning "WINRM-HTTP-In-TCP-PUBLIC rule was not found"

                report |> Array.iter (fun (x, _) -> this.WriteObject x)
            | _ -> this.WriteWarning "No successful network logons was detected. Cmdlet did nothing."

        | _ -> Err.permissionDenied "Protect-FromBruteforce" |> this.WriteError


(*
        .SYNOPSIS
        Reset remote scope of firewall rules back to ANY.

        .DESCRIPTION
        Reset remote scope of firewall rules back to ANY.

        .EXAMPLE
        #Reset default RDP rules to ANY.
        Unprotect-Bruteforce -RDP

        .INPUTS
        None.

        .OUTPUTS
        None.
*)
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
            if this.RDP.IsPresent then
                match SetRule.RDP_TCP + "ANY" |> Pwsh.invoke with
                | Some _ -> this.WriteVerbose "Standard firewall rule was reset for RDP TCP"
                | _ -> this.WriteWarning "RemoteDesktop-UserMode-In-TCP rule was not found"

                match SetRule.RDP_UDP + "ANY" |> Pwsh.invoke with
                | Some _ -> this.WriteVerbose "Standard firewall rule was reset for RDP UDP"
                | _ -> this.WriteWarning "RemoteDesktop-UserMode-In-UDP rule was not found"

            if this.SMB.IsPresent then
                match SetRule.SMB + "ANY" |> Pwsh.invoke with
                | Some _ -> this.WriteVerbose "Standard firewall rule was reset for SMB"
                | _ -> this.WriteWarning "FPS-SMB-In-TCP rule was not found"

            if this.WinRM.IsPresent then
                match SetRule.WINRM + "ANY" |> Pwsh.invoke with
                | Some _ -> this.WriteVerbose "Standard firewall rule was reset for WINRM"
                | _ -> this.WriteWarning "WINRM-HTTP-In-TCP-PUBLIC rule was not found"
        | _ -> Err.permissionDenied "Unprotect-FromBruteforce" |> this.WriteError
