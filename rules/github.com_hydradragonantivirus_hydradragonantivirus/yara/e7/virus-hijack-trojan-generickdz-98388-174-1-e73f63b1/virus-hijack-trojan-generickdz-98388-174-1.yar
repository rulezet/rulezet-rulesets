rule Virus_Hijack_Trojan_GenericKDZ_98388_174_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_174_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8e6599496a937fee16fca069d14c9acfdd8c7f39ff1848c5ad7e2dbf08baebb"

  strings:
    $s1 = "AmYl#0" fullword ascii
    $s2 = "hICk,k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}