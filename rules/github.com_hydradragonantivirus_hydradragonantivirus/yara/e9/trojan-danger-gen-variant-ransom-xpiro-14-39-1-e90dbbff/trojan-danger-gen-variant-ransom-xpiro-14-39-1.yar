rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_39_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_39_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03de94bd8e4b08c8fc88023a5ee15265a123a541165a735789da91dc07331410"

  strings:
    $s1 = "\\IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}