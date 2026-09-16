rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f954e312f2e79c31a1763767171e127d6bb74751030cc0ad45d5a2248a9e9b1"

  strings:
    $s1 = "HeEL!T" fullword ascii
    $s2 = "piTy%5o" fullword ascii
    $s3 = "prod,&" fullword ascii
    $s4 = "tERP`1" fullword ascii
    $s5 = "6?LUrK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}