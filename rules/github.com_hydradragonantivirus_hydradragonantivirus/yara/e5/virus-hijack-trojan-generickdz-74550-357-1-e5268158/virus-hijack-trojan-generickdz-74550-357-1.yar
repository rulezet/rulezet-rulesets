rule Virus_Hijack_Trojan_GenericKDZ_74550_357_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_357_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20335a06601250a7351a22e224028be2211475d64de9bc94d3712e7af3d8588e"

  strings:
    $s1 = "sENT[u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}