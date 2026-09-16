rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4cc84904ed77afbe4192e6b18ad235d3787973c02cbaa9d22e2a3426da7a848"

  strings:
    $s1 = "kIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}