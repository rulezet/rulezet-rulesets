rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_251_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_251_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b9dd57377ca50e6dba39e5dd431032581167537b93145290504dd15b50ebd33"

  strings:
    $s1 = ";IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii
    $s2 = "qV!MaTE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}