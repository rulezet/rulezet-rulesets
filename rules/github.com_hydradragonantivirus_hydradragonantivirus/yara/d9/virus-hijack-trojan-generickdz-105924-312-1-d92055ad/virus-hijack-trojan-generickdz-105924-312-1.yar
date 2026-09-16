rule Virus_Hijack_Trojan_GenericKDZ_105924_312_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_312_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ba78f86766beada107253d3b96d85707bb41d304b732d121ce94c2aced4be7e"

  strings:
    $s1 = "*\"chAR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}