rule Trojan_Danger_Generic_Dacic_1A7FA519_A_61743973_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.61743973_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "576b00f8d69122f16c2d13e6be72f7b09b272a1fbccff67733c7d804eae61edd"

  strings:
    $s1 = "pSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}