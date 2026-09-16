rule Virus_Hijack_Trojan_GenericKDZ_98388_144_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_144_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e54306e47fd570b3bd1e3d9d1b1b904082b6edacd9de4c4627d0784317def483"

  strings:
    $s1 = "`tApa[I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}