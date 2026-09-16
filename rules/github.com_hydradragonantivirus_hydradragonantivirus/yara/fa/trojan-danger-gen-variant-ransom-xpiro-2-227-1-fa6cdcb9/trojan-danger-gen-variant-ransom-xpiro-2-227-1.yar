rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_227_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_227_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bd0da410662ce3f564fcaec4cdf227742ac5256d957a40cefc5bf5a3d4ecabf"

  strings:
    $s1 = "1America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}