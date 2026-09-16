rule Virus_Hijack_Trojan_EmotetU_Gen_mS0_h8VZXzfi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.mS0@h8VZXzfi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5602a36105d8870d086e30f77b8072cfe0419e78b383812e9ad14af964cfcd1e"

  strings:
    $s1 = "preagriculture" fullword wide
    $s2 = "Eudaemonism" fullword wide
    $s3 = "Slodge" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}