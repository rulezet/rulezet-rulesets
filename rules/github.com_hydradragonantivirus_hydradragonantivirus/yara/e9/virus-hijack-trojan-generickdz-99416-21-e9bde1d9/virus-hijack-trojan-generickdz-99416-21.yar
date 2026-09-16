rule Virus_Hijack_Trojan_GenericKDZ_99416_21 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca1e32549a4cc082647816b346f9aede17ee3231ec49727af670d0fa9a88d3fd"

  strings:
    $s1 = "7qUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}