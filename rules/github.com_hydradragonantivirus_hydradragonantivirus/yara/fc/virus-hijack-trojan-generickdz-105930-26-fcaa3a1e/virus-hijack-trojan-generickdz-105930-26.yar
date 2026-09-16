rule Virus_Hijack_Trojan_GenericKDZ_105930_26 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f0c75b694374a59d757d1f3bf0da0a922cd323155001c497edb4a4b266df31f"

  strings:
    $s1 = "TOUR LICE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}