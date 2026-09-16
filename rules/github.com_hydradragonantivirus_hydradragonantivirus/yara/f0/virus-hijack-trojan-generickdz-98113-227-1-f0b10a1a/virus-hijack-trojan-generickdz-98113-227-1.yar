rule Virus_Hijack_Trojan_GenericKDZ_98113_227_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_227_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc8f3dc2c4173a755a97544b2685cb7e066c0fe15eb6498c1ac4b8a3f4fe90bc"

  strings:
    $s1 = "l>SNEb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}