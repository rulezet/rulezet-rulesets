rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_86_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_86_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1122c1851a1354dce6cbf364117dc16970dbdaf6ef1cb1498e4a716a807e844f"

  strings:
    $s1 = "SSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii
    $s2 = "SSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii
    $s3 = "7<?CeTi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}