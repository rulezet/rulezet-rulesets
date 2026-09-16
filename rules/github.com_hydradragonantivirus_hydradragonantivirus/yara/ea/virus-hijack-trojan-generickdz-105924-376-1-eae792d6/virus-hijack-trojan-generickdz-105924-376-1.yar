rule Virus_Hijack_Trojan_GenericKDZ_105924_376_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_376_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1527afc2f8ee5dd4bdf5af66d0db06a2ce59a1d5205c03f250538d3d0e3f4dd"

  strings:
    $s1 = ";LeaK{n6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}