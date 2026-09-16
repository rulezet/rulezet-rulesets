rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_52 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_52.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8336319ec42785c56af9e8b6d059fc79fa21e902ca51fbbc092638edfd73448c"

  strings:
    $s1 = "Microsoft Office Publisher 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}