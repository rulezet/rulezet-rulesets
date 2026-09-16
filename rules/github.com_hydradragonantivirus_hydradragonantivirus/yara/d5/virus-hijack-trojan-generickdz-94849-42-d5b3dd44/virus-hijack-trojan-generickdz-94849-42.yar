rule Virus_Hijack_Trojan_GenericKDZ_94849_42 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_42.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2a95584dcc878fcf47b7fbbcabf1841c00bf09a379ba7132012c821f799dc85"

  strings:
    $s1 = "=r&fArE)_I" fullword ascii
    $s2 = "g@dhow" fullword ascii
    $s3 = "9b@@fYkE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}