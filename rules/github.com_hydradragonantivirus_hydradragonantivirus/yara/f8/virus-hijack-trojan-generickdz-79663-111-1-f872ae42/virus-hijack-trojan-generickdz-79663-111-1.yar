rule Virus_Hijack_Trojan_GenericKDZ_79663_111_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_111_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1785f345b76b1f9fec8fcb8e62f4ab98a8c70c2070324c9e44b6a641136c9f00"

  strings:
    $s1 = "Neat{xt" fullword ascii
    $s2 = "loca!sf" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}