rule Virus_Hijack_Trojan_GenericKDZ_103285_28 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94206d4c220ceed92928e0c6181b9beb5ff4f19ab7689f8b333e0c2a22ccce52"

  strings:
    $s1 = "lFa neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}