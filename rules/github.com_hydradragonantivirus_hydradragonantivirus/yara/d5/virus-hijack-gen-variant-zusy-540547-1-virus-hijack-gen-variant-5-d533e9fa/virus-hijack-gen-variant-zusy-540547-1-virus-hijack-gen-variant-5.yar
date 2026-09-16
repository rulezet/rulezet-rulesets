import "pe"
rule _Virus_Hijack_Gen_Variant_Zusy_540547_1_Virus_Hijack_Gen_Variant_5 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Variant.Zusy.540547_1.vir, Virus.Hijack_Gen.Variant.Zusy.540547_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f56cea2a14c53c7b83caad6a150b2587aeaa73d4bf09ea1af7180a559c066303"
    hash2       = "ef22e65a7624c84860b935362ceef3eab804c9c9b4ef40b556bd7bc1fcba7dc9"

  strings:
    $s1 = "pENd!Y~jn" fullword ascii
    $s2 = "ruST}<" fullword ascii
    $s3 = "?Y{LyrA" fullword ascii
    $s4 = "A<;tHEn" fullword ascii
    $s5 = "[weLs#f" fullword ascii
    $s6 = ")E&SatE&" fullword ascii
    $s7 = "97$KnAb" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "8a7144716015fefc4920a45528d0fa9a" and (all of them)
    ) or (all of them)
}