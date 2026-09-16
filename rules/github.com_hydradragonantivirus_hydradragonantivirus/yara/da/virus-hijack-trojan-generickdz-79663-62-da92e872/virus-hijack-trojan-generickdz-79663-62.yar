rule Virus_Hijack_Trojan_GenericKDZ_79663_62 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_62.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7b6dfabd39a318da774e04cc23e7679ad9f00175b281520a5adb73e598c87d7"

  strings:
    $s1 = "mARl>)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}