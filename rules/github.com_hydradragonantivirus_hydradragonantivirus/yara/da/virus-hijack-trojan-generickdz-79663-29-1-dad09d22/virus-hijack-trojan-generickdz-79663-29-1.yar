rule Virus_Hijack_Trojan_GenericKDZ_79663_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98bd7c0fceb9644a0173954a3456a35dea18ee01c2f8e74c1ea85f469cd74f48"

  strings:
    $s1 = " w(stUM" fullword ascii
    $s2 = "$\"hUrL`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}