rule Virus_Autorun_Gen_Variant_Genie_10_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Gen.Variant.Genie.10_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f5838a3d2357832d439f49c6125bc1a7ef39454f2c1838eb27503b7260678df"

  strings:
    $s1 = "Python 3.11 Module Docs (64-bit).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}