rule Virus_Hijack_Trojan_GenericKDZ_98388_102_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_102_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35fda56a78f0a638133ec23c886297ffb5e06a693f0fbffc3051bf99ea028b22"

  strings:
    $s1 = "BoAr&X" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}