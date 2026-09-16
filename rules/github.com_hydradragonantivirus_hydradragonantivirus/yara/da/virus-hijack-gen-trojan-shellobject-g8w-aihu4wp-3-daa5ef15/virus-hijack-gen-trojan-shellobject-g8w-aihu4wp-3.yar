rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b48622cd3cd474a5740d8f018977be3bdc2db7b27a71dc31606de0cfd4e6041d"

  strings:
    $s1 = "AWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}