rule Virus_Hijack_Gen_Trojan_ShellObject_fCY_aijlKSl_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9240fd84d78e86472142e0e8034f985c05493688465eedc746fd3ff7f778ad09"

  strings:
    $x1 = "Usage: %ls [ProcessID [ThreadId [Flags[:MiniDumpFlags] [SqlInfoPtr [DumpDir [ExceptionRecordPtr [ContextPtr [ExtraFile] [Pattern" wide
    $s2 = "WerReportAddfile SQLDumpFile failed, error: 0x%08X" fullword wide
    $s3 = ".SQL External minidumpe" fullword wide
    $s4 = "<description>Windows Error Reporting</description>" fullword ascii
    $s5 = "WerReportAddFile Extra File succeeded." fullword wide
    $s6 = "AHKCU\\Software\\Microsoft\\Internet Explorer\\Settings\\Anchor Color" fullword ascii
    $s7 = "$@Unknown exception" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}