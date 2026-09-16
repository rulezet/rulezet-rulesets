rule Virus_Hijack_Gen_Variant_Zusy_540547 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Zusy.540547.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "022da958da84efa83ece5f9c98c63d9dccf0dba7ecc0a235e3add58453e16874"

  strings:
    $s1 = "%LALo@,4" fullword ascii
    $s2 = "OcHt&k" fullword ascii
    $s3 = "VeIl%T" fullword ascii
    $s4 = "birL;f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}