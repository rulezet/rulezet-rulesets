rule Virus_Hijack_Trojan_GenericKDZ_98113_339 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_339.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dc729ff912c5b38b48bf279911a8db2351bb17396189ae22ae9c91360470852"

  strings:
    $s1 = "7by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}