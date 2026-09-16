rule Trojan_Autorun_Gen_Variant_Barys_95064_29 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064_29.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f4f76998d08d560261879df9fa51a02b65cc4436c1f8ec07d345eeac2f8db93"

  strings:
    $s1 = "EW)YARr" fullword ascii
    $s2 = "LoDe<{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}