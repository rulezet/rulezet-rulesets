rule Trojan_Danger_Trojan_GenericKD_67269844_6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c32cda85cb3b7d557591d4f9fb85c0f20503ef7e8c8933bb9260539b6d2b04e9"

  strings:
    $s1 = "5u>ErUc" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}