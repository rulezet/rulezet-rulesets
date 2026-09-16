rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aCkwazk_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4207522d5b7dd3df21da3d88e00596c28acede0433cec864d11bafd52a5e76dc"

  strings:
    $s1 = "lamP x" fullword ascii
    $s2 = "om]rooF:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}