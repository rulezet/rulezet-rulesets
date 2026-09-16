rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_509_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_509_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee13671845f33735f5e229270e234ac0e7acafe7e2f86b4f1c28f1656911555f"

  strings:
    $s1 = "sOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}