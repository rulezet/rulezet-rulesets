rule Virus_Hijack_Trojan_GenericKDZ_74550_57_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_57_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d59267707a4912cb3cfc8d8c39205bbeaaef806ca77656736e47c44924b49b23"

  strings:
    $s1 = "{A)%EyED" fullword ascii
    $s2 = "Utum[]" fullword ascii
    $s3 = "SAcKw2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}