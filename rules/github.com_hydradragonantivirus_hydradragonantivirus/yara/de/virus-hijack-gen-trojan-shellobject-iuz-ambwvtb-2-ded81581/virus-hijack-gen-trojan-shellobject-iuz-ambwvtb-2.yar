rule Virus_Hijack_Gen_Trojan_ShellObject_iuZ_amBwvTb_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iuZ@amBwvTb_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef794cf242b2ec7d2fd30e183e573d3753f3a6ee732651b9c247db599e087fc9"

  strings:
    $s1 = "jUte:R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}