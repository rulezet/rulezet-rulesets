rule _Virus_Hijack_Gen_Trojan_ShellObject_avZ_amBwvTb_5_2_VirusShareB_443 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.avZ@amBwvTb_5_2.vir, VirusShareBackDoorMeterpreter216.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b10b1c0f9218bf974fccbeda602c823502f9927174b22df53db4f1a7daf67ffc"
    hash2       = "2209ac09da78031d7bdcd91b05041e41a2dcbd0f2c842aa839ba3d18480e2c01"

  strings:
    $s1  = " = : missing method DnsRecordListFreeFLE Standard TimeGC assist markingGMT Standard TimeGTB Standard TimeGetCurrentProcessGetSho" ascii
    $s2  = "invalid pointer found on stacknotetsleep - waitm out of syncprotocol wrong type for socketrunqputslow: queue is not fullruntime:" ascii
    $s3  = "invalid pointer found on stacknotetsleep - waitm out of syncprotocol wrong type for socketrunqputslow: queue is not fullruntime:" ascii
    $s4  = "raceGCSweepStartfunction not implementedgcDrainN phase incorrectinitSpan: unaligned baselevel 2 not synchronizedlink number out " ascii
    $s5  = "Eastern Standard TimeAfghanistan Standard TimeExpandEnvironmentStringsWGODEBUG: can not enable \"GetQueuedCompletionStatusKalini" ascii
    $s6  = "d TimeCape Verde Standard TimeCertFreeCertificateChainCreateToolhelp32SnapshotGetUserProfileDirectoryWMagallanes Standard TimeMo" ascii
    $s7  = "nd Standard TimePostQueuedCompletionStatusSaint Pierre Standard TimeSouth Africa Standard TimeW. Australia Standard TimeWest Pac" ascii
    $s8  = "possible type kindruntime: levelShift[level] = runtime: marking free object runtime: p.gcMarkWorkerMode= runtime: split stack ov" ascii
    $s9  = "structure needs cleaning bytes failed with errno= to unused region of span with too many arguments AUS Central Standard TimeAUS " ascii
    $s10 = " untyped locals 0123456789abcdefCreateDirectoryWDnsNameCompare_WFlushFileBuffersGC scavenge waitGC worker (idle)GODEBUG: value " ascii
    $s11 = " Standard TimeEkaterinburg Standard TimeGODEBUG: can not disable \"GetFileInformationByHandleLine Islands Standard TimeNewfoundl" ascii
    $s12 = "Argentina Standard TimeAstrakhan Standard TimeCertGetCertificateChainE. Africa Standard TimeE. Europe Standard TimeFreeEnvironme" ascii
    $s13 = "ntevideo Standard TimeNorth Asia Standard TimePacific SA Standard TimeSA Eastern Standard TimeSA Pacific Standard TimeSA Western" ascii
    $s14 = " Standard TimeUS Eastern Standard Time\", required CPU feature" fullword ascii
    $s15 = "as no free stacksstack growth after forksystem huge page size (work.nwait > work.nprocAzerbaijan Standard TimeBangladesh Standar" ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}