rule Virus_Hijack_Trojan_Peed_Gen_39_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_39_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae74c996ef25c65b67c6b597e37da8e726671e1ed59013101c065a3ddb05cb9d"

  strings:
    $s1 = "a&wAnY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}