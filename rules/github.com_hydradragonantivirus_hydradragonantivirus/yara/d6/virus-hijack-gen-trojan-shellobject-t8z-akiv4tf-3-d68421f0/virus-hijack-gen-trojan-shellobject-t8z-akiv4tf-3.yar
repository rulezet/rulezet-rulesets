rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aKiV4Tf_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aKiV4Tf_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af6e233adf1651e4c904c55d8a3fc0a3ec084632103744f75637b097c7dee148"

  strings:
    $s1 = "kvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}