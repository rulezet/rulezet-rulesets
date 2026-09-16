rule Virus_Hijack_Trojan_EmotetU_Gen_m01_hOi7FRgi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.m01@hOi7FRgi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b35565b4b8c2f17e5e317c70990254993a158739db2cf858b313852c1aeb4c7"

  strings:
    $s1 = "frownful" fullword wide
    $s2 = "conservant" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}