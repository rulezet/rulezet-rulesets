rule Virus_Hijack_Trojan_GenericKDZ_98113_388 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_388.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cd03d25f78a0ad2f192ab59ca6fe21c9e60a7147d38e2eb083833ab38f93992"

  strings:
    $s1 = "Rby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}