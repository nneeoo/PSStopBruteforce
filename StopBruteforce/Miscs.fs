﻿module Miscs

open System
open System.Diagnostics
open System.Net
open System.Management.Automation

[<Struct; NoEquality; NoComparison>]
type Report =
    { Attempts: int
      IpAddress: IPAddress
      HostName: string }

[<RequireQualifiedAccess>]
module Pwsh =
    let invoke (x: string) =
        use pwsh = PowerShell.Create().AddScript(x)

        match pwsh.Invoke() with
        | res when res <> null  && res.Count > 0 -> Some res
        | _ -> None

let tryResolve (x: IPAddress) =
    try
        Dns.GetHostEntry(x).HostName
    with
    | _ -> "None"

module EventLog =
    let getFailureAudit (l: float) =
        let timeFilter = DateTime.Now.AddHours(-l)

        let securityLogs =
            EventLog.GetEventLogs()
            |> Array.filter (fun (i: EventLog) -> i.Log = "Security")
            |> Array.map (fun i -> i.Entries)
            |> Array.head

        [| for log in securityLogs do
               if log.InstanceId = 4625L
                  && log.EntryType = EventLogEntryType.FailureAudit
                  && log.TimeWritten > timeFilter
                  && log.ReplacementStrings.[3] = "0x0" then

                   match log.ReplacementStrings.[19] |> IPAddress.TryParse with
                   | true, x -> yield x
                   | _ -> () |]
        |> Array.groupBy id
        |> Array.Parallel.map
            (fun i ->
                let a, b = i

                { Attempts = b.Length
                  IpAddress = a
                  HostName = tryResolve a })


    let getSuccessAudit (l: float) =
        let timeFilter = DateTime.Now.AddHours(-l)

        let securityLogs =
            EventLog.GetEventLogs()
            |> Array.filter (fun (i: EventLog) -> i.Log = "Security")
            |> Array.map (fun i -> i.Entries)
            |> Array.head

        [| for log in securityLogs do
               if log.InstanceId = 4624L && log.EntryType = EventLogEntryType.SuccessAudit && log.TimeWritten > timeFilter then
                   match log.ReplacementStrings.[18] |> IPAddress.TryParse with
                   | true, x when x <> IPAddress.Loopback -> yield x
                   | _ -> () |]
        |> Array.groupBy id
        |> Array.Parallel.map
            (fun i ->
                let a, _ = i
                a)