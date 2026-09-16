rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "372be47b8adbbaee8a86e09718deae78ff105fe9c3e4a7c287ec29e7ad915334"

  strings:
    $s1 = "LBuilt using an evaluation version of {smartassembly}. Cannot be distributed." fullword ascii
    $s2 = " exile" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}