rule Virus_Infector_Gen_Variant_Ransom_TeslaCrypt_98_7 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.98_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "146c0d102a4eb3270e7766ccf6764ea22b3f9426e8bec2939d5a8218b3c20a52"

  strings:
    $s1 = ":stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Pho" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}