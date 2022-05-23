module Miscs

open System
open System.Diagnostics
open System.Net
open System.Management.Automation
open System.Linq

[<Struct; NoEquality; NoComparison>]
type Report =
    { Attempts: int
      IpAddress: IPAddress
      HostName: string
      Names: string array }

[<Struct; NoEquality; NoComparison>]
type Entry = { IpAddress: IPAddress; Name: string }

[<RequireQualifiedAccess>]
module Pwsh =
    let invoke (x: string) =
        use pwsh = PowerShell.Create().AddScript(x)

        match pwsh.Invoke() with
        | res when res <> null && res.Count > 0 -> Some res
        | _ -> None

let tryResolve (x: IPAddress) =
    try
        Dns.GetHostEntry(x).HostName
    with
    | _ -> "None"

module EventLog =
    let getSecurityLogs () =
        EventLog.GetEventLogs() |> Array.find (fun (i: EventLog) -> i.Log = "Security")

    let getFailureAudit (l: float) =
        let timeFilter = DateTime.Now.AddHours(-l)

        getSecurityLogs().Entries.Cast()
        |> Array.ofSeq
        |> Array.filter (fun (log: EventLogEntry) ->
            log.InstanceId = 4625L && log.EntryType = EventLogEntryType.FailureAudit && log.TimeWritten > timeFilter)
        |> Array.Parallel.choose (fun log ->
            match log.ReplacementStrings.[19] |> IPAddress.TryParse with
            | true, x when x <> IPAddress.Loopback ->
                { IpAddress = x
                  Name = log.ReplacementStrings.[5] }
                |> Some
            | _ -> None)
        |> Array.groupBy (fun i -> i.IpAddress)
        |> Array.Parallel.map (fun (ip, entries) ->
            { Attempts = entries.Length
              IpAddress = ip
              HostName = tryResolve ip
              Names = entries |> Array.map (fun i -> i.Name) |> Array.distinct })


    let getSuccessAudit (l: float) =
        let timeFilter = DateTime.Now.AddHours(-l)

        getSecurityLogs().Entries.Cast()
        |> Array.ofSeq
        |> Array.filter (fun (log: EventLogEntry) ->
            log.InstanceId = 4624L && log.EntryType = EventLogEntryType.SuccessAudit && log.TimeWritten > timeFilter)
        |> Array.Parallel.choose (fun log ->
            match log.ReplacementStrings.[18] |> IPAddress.TryParse with
            | true, x when x <> IPAddress.Loopback -> Some x
            | _ -> None)

module SetRule =
    [<Literal>]
    let RDP_TCP = @"Set-NetFirewallRule -PassThru -Name 'RemoteDesktop-UserMode-In-TCP' -RemoteAddress "

    [<Literal>]
    let RDP_UDP = @"Set-NetFirewallRule -PassThru -Name 'RemoteDesktop-UserMode-In-UDP' -RemoteAddress "

    [<Literal>]
    let SMB = @"Set-NetFirewallRule -PassThru -Name 'FPS-SMB-In-TCP' -RemoteAddress "

    [<Literal>]
    let WINRM = @"Set-NetFirewallRule -PassThru -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress "

    [<Literal>]
    let Sbf = @"Set-NetFirewallRule -PassThru -Name 'Stop-Bruteforce' -RemoteAddress "

module NewRule =
    [<Literal>]
    let Sbf =
        @"New-NetFirewallRule -Name 'Stop-Bruteforce' -DisplayName 'Stop-Bruteforce' -Action Block -Direction Inbound -Enabled True -RemoteAddress "

module Err =
    let permissionDenied x =
        let exn = exn ("To use " + x + " , you need administrator rights")
        ErrorRecord(exn, "1", ErrorCategory.PermissionDenied, x)

    let newRule x =
        let exn = exn "Can not create new firewall rule"
        ErrorRecord(exn, "1", ErrorCategory.InvalidResult, x)
