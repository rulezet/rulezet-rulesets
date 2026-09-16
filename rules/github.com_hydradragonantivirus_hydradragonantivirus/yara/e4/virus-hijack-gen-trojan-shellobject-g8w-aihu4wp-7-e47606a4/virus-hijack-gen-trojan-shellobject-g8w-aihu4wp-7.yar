rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ed6b1251255ac6d548a90e0d75298cec42544bd17184f72ddeda743cd2d18aa"

  strings:
    $s1 = "CWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}