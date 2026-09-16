rule Virus_Hijack_Trojan_GenericKDZ_98113_177_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_177_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb2b7dafa6519864ed390373c50edbbda7898fc1c519f30ac3b2a82b80053122"

  strings:
    $s1 = "+$GAvE" fullword ascii
    $s2 = "{F]gyve" fullword ascii
    $s3 = "]!DUMA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}