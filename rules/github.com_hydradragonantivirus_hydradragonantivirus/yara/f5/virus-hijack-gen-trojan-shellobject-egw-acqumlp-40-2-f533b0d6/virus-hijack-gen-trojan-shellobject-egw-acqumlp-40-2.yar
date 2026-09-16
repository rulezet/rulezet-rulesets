rule Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_40_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_40_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1edd69176af7b518a14053faef99e473a0b753a4da9504787fde8d7328f1849"

  strings:
    $s1 = "Q * FROM" fullword ascii
    $s2 = "Menu@O#" fullword ascii
    $s3 = "echo Y|s}h6P" fullword ascii
    $s4 = "#BOUNDARY#\"W,`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}