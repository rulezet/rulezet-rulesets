rule Virus_Hijack_Trojan_GenericKDZ_99416_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd5a902da4db9483ce836e092cb0a001ce2809a4d9e57bf07011cdd44aaaf370"

  strings:
    $s1 = "!User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}