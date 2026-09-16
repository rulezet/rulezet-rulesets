rule Virus_Hijack_Trojan_GenericKDZ_105924_36_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_36_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b132a42bb855c016d3a3d8c2b9b96129c19150e9be50c8e7fd39d4d6df33d226"

  strings:
    $s1 = "plEA]g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}