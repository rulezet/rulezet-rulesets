rule Virus_Hijack_Trojan_GenericKDZ_105924_94_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_94_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2abd04eee4b213a049cf525dbabbdbcc25b16ba3a9c0f6f8ad825786bea78b9e"

  strings:
    $s1 = "SOYA#O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}