rule Virus_Hijack_Trojan_GenericKDZ_98113_95_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_95_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ef883442e2ee4296389caaca51f93c031e79690c8d829b70428e95a7fc4e09a"

  strings:
    $s1 = "JEEp%%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}