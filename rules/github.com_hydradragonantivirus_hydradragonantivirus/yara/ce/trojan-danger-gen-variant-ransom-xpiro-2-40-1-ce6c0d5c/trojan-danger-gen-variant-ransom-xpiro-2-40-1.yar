rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_40_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_40_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ae5f709a4f7f9d239561b964947e486d259f7a60b4b359bb944a39644f80563"

  strings:
    $s1 = "preagriculture" fullword wide
    $s2 = "Eudaemonism" fullword wide
    $s3 = "Slodge" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}