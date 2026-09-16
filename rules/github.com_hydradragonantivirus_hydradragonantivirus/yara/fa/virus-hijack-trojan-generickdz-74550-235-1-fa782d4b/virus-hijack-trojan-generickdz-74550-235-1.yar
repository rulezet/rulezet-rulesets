rule Virus_Hijack_Trojan_GenericKDZ_74550_235_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_235_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23dc395926dacf4466e9d9e027db5d6ded1b4c2d603b7ee318d0556a16e97a4c"

  strings:
    $s1 = "M`FUJi`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}