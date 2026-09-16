rule Virus_Hijack_Trojan_GenericKDZ_79663_99_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_99_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43d7bd6e1db51e7ed541858a0901a5bab13c8da92f0fab37cb3b9a4e920b144e"

  strings:
    $s1 = "Grid%2m" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}