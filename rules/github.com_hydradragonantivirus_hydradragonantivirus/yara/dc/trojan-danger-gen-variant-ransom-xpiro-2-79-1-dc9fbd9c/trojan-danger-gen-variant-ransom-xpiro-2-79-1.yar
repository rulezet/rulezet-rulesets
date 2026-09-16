rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_79_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_79_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3722dc648f5acccca922e54969df63002a314756cc1aa4bb0eb449a5bd9f677c"

  strings:
    $s1 = "KJpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}