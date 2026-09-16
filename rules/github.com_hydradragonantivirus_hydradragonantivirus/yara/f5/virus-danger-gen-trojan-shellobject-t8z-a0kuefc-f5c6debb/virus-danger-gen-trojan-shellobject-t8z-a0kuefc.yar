rule Virus_Danger_Gen_Trojan_ShellObject_t8Z_a0kuefc {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.t8Z@a0kuefc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6d84d2b054923ca22f9d1be8132bea52e73b4e7113c4f551a8f23afdaab1fea"

  strings:
    $s1 = "/+virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}