rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_149_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_149_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f88b115f06614a4a9350e37141ac6242980fa7a5f9f479ad0412b2c2bbb40ca"

  strings:
    $s1 = "/Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}