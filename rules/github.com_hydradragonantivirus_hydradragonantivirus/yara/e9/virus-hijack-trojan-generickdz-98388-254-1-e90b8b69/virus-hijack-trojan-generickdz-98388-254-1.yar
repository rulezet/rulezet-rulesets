rule Virus_Hijack_Trojan_GenericKDZ_98388_254_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_254_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd0cd1dea0b20f12fee19534bc1e544a1e91ec2fdaeeaf960cbae4220238ff82"

  strings:
    $s1 = "C:KOku" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}