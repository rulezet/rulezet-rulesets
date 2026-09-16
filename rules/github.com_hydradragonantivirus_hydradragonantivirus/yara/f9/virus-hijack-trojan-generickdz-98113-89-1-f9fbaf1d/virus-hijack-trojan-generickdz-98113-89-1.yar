rule Virus_Hijack_Trojan_GenericKDZ_98113_89_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_89_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8303046c2a0863b27a342dacfc7f7821911ccb101820ceb5048d39663f6e1f3f"

  strings:
    $s1 = "T{GRIT" fullword ascii
    $s2 = "p#dunG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}