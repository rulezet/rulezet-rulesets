rule Virus_Hijack_Trojan_GenericKDZ_98113_410_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_410_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f804f29727e65f128700ca2c09e920e7083f5756659c08f2e1b40de49b25e5c7"

  strings:
    $s1 = "hEiR]C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}