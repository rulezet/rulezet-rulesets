rule Virus_Danger_Gen_Variant_Midie_100599 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Variant.Midie.100599.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bab8966b51751db7cc4d0341425d0ae4ebc39e8f11970e9e4451944f67cf26f0"

  strings:
    $s1 = "Conexant Systems Inc.  All rights reserved." fullword wide
    $s2 = "Conexant Audio" fullword wide
    $s3 = "^ PALe'p" fullword ascii
    $s4 = "e`tHOw" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}