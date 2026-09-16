rule Trojan_Hooker_Gen_Variant_Barys_4848_4 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Gen.Variant.Barys.4848_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efd8522e728dbb783bb8c317f90a8be40bfd161f2886d4b0eb41a266d8f50a20"

  strings:
    $s1 = "SECURE APPLICATION DEVELOPMENT1)0'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}