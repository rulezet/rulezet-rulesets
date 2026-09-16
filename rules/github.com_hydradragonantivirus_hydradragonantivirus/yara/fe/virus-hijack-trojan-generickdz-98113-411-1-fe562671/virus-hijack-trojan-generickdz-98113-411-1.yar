rule Virus_Hijack_Trojan_GenericKDZ_98113_411_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_411_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e69b13a95e96318603a6d794fa6b7a2cc6e51949f7d4b99640921a5b7e339641"

  strings:
    $s1 = "{ipId?'" fullword ascii
    $s2 = "{RP(miKE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}