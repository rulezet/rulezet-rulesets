rule Virus_Hijack_Trojan_GenericKDZ_98388_109_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_109_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ead41d70a0aa71a1ef6e96441018fd7a715681c13cc0a28119c4b10db7190d21"

  strings:
    $s1 = ",TIFT}" fullword ascii
    $s2 = "Y:!atwO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}