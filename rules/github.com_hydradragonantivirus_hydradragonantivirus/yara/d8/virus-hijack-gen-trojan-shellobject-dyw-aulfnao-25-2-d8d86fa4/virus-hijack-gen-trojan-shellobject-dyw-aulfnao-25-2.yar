rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_auLFnao_25_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@auLFnao_25_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e7ac6a29a7160bb1db5f173de121ae745bbc764d890678aaf55677e163a0e88"

  strings:
    $s1 = "r}DaRR?" fullword ascii
    $s2 = "U:shOW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}