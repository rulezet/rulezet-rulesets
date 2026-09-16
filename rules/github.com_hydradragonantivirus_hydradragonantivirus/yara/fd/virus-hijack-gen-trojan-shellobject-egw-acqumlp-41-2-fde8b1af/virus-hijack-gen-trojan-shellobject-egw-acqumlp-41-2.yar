rule Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_41_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_41_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ef98827310b6abc8ddfd0cf613d307f01bba42e0b787f56119a22ae865af93e"

  strings:
    $s1 = "Q * FROM" fullword ascii
    $s2 = "Menu@O#" fullword ascii
    $s3 = "echo Y|s}h6P" fullword ascii
    $s4 = "#BOUNDARY#\"W,`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}