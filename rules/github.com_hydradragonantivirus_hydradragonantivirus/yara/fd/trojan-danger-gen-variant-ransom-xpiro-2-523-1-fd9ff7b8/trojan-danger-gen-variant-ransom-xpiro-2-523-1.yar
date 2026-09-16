rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_523_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_523_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a924eee5496e946ace08f19e044d9102e4db093bbafe8f113d8e1bca4e9de46"

  strings:
    $s1 = "KOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}