rule Virus_Hijack_Gen_Trojan_Brresmon_Gen_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.Brresmon.Gen.1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20dee04881e3440e944f91e2bef35acc5e8d6dbd6f5edd9526ad676550713551"

  strings:
    $s1 = "  is registered trademark of Kaspersky Lab ZAO." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}