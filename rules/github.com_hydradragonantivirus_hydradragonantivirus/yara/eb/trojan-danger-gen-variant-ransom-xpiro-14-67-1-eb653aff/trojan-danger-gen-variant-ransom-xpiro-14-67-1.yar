rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_67_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_67_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9972383142ea1b54f5bb5e55ee7cd3055bfadd05bbcf2362d8f591ab652e6f6d"

  strings:
    $s1 = "sProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}