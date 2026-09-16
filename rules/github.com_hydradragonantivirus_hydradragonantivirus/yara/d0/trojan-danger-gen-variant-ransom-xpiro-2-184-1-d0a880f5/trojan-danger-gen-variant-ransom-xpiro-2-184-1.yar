rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_184_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_184_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9734cc0c823af615f64f66ab599e922e9766d76d6da8cbb82a58eabd14665830"

  strings:
    $s1 = "xorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}