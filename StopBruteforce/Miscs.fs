module Miscs

open System
open System.Diagnostics
open System.Net
open System.Management.Automation

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
    let getFailureAudit (l: float) =
        let timeFilter = DateTime.Now.AddHours(-l)

        let securityLogs = EventLog.GetEventLogs() |> Array.find (fun (i: EventLog) -> i.Log = "Security")

        [| for log in securityLogs.Entries do
               if log.InstanceId = 4625L
                  && log.EntryType = EventLogEntryType.FailureAudit
                  && log.TimeWritten > timeFilter
                  && log.ReplacementStrings.[3] = "0x0" then
                   yield log |]
        |> Array.Parallel.choose
            (fun log ->
                match log.ReplacementStrings.[19] |> IPAddress.TryParse with
                | true, x when x <> IPAddress.Loopback ->
                    { IpAddress = x
                      Name = log.ReplacementStrings.[5] }
                    |> Some
                | _ -> None)
        |> Array.groupBy (fun i -> i.IpAddress)
        |> Array.Parallel.map
            (fun (ip, entries) ->
                { Attempts = entries.Length
                  IpAddress = ip
                  HostName = tryResolve ip
                  Names = entries |> Array.map (fun i -> i.Name) |> Array.distinct })


    let getSuccessAudit (l: float) =
        let timeFilter = DateTime.Now.AddHours(-l)

        let securityLogs = EventLog.GetEventLogs() |> Array.find (fun (i: EventLog) -> i.Log = "Security")

        [| for log in securityLogs.Entries do
               if log.InstanceId = 4624L
                  && log.EntryType = EventLogEntryType.SuccessAudit
                  && log.TimeWritten > timeFilter then
                   yield log |]
        |> Array.Parallel.choose
            (fun log ->
                match log.ReplacementStrings.[18] |> IPAddress.TryParse with
                | true, x when x <> IPAddress.Loopback -> Some x
                | _ -> None)
        |> Array.groupBy id
        |> Array.Parallel.map fst
