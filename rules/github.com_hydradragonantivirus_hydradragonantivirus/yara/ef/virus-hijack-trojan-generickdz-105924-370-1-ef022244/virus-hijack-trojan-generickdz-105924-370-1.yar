rule Virus_Hijack_Trojan_GenericKDZ_105924_370_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_370_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "581d16128e511d416496cdabceff0029c89bae597b35ab4bf9c7f3a53c24b1eb"

  strings:
    $s1 = "X&forB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}