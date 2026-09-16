rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aeOesjp_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aeOesjp_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "425c0c7248efe3cbde908d78ab48904887dab3ae88e70de5292072f465fbd205"

  strings:
    $s1 = "Executing task" fullword ascii
    $s2 = "Feedback pipe (SQM/CEIP) enabled?" fullword wide
    $s3 = "Waiter thread" fullword ascii
    $s4 = "@Turning On PerfScenarios in PerfScenario initialization" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}