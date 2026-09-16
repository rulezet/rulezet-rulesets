rule Virus_Hijack_Trojan_GenericKDZ_105924_295_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_295_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8784b714783d7da6d085d96a3e0ca9afc0e4fa7e29d2b950fba96ab7515adca0"

  strings:
    $s1 = "c(2\"!\"RINk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}