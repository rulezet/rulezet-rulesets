rule Virus_Injector_Trojan_GenericKDZ_100120_1 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Trojan.GenericKDZ.100120_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9921e3c585a4ff3ee8a220e9c9c6e5ecb5e9093543f422d5dfad85cc2d700af"

  strings:
    $s1 = "Y\"Lacy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}