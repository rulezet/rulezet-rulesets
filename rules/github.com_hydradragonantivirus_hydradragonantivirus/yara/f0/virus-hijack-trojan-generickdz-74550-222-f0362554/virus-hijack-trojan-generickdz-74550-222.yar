rule Virus_Hijack_Trojan_GenericKDZ_74550_222 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_222.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85008fc2494e1210926afb3be47e97b67ad9def47f674e020b43e8dd88037e0c"

  strings:
    $s1 = "D<KHET" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}