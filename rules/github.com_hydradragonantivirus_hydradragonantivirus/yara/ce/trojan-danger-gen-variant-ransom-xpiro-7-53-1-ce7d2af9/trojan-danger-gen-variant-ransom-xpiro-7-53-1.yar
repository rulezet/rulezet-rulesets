rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_53_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_53_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "965d819924c58c6f99fd775f14cfc141f603dcf2ce1cd91260161f3d149d1c09"

  strings:
    $s1 = "uSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}