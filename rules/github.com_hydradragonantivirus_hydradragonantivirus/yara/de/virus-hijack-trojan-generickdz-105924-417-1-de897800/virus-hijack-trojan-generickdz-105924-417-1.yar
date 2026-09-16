rule Virus_Hijack_Trojan_GenericKDZ_105924_417_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_417_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29b9086c86e43c3f6af26df209f639cbc0f59fbee316bab640589bc6052f29e8"

  strings:
    $s1 = "cOYO,{" fullword ascii
    $s2 = "K}goaf" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}