rule Virus_Hijack_Trojan_GenericKDZ_98388_54_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_54_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de99c6008b22bf93c046f59abfce98c436fc0b32d7a5e24f67c69e73304998d9"

  strings:
    $s1 = "p]LEst" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}