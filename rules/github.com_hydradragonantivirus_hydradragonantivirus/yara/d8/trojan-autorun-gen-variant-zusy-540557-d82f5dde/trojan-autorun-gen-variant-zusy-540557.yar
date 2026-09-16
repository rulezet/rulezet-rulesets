rule Trojan_Autorun_Gen_Variant_Zusy_540557 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Zusy.540557.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09f23025d715988cc065bd26a45c08db8500d7078c93e404842ff62b0756c436"

  strings:
    $s1 = "LIte&T4" fullword ascii
    $s2 = "PUky[HJ" fullword ascii
    $s3 = "#qsD:Homo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}