rule Virus_Hijack_Trojan_GenericKDZ_74550_375_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_375_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7a3cc4738eabb5f2e31fe3e06221444d51381bb399231b332b0843ea1d8eb59"

  strings:
    $s1 = "YiLT:|" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}