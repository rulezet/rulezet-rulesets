rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_aCNb4Uo_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6bcd18f3d20fa6f816d80667a52e5076d808a73374c559c2a75177538733105"

  strings:
    $s1 = "CORE;5" fullword ascii
    $s2 = "%4jsk%peBA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}