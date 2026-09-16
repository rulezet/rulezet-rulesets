rule Virus_Hijack_Trojan_GenericKDZ_74550_82 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_82.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f7a71d014f4b4a5664ff9413aa2a0bca17c2903d2c50af9477eddf1740d3989"

  strings:
    $s1 = "]SaDe;" fullword ascii
    $s2 = "H)SaMp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}