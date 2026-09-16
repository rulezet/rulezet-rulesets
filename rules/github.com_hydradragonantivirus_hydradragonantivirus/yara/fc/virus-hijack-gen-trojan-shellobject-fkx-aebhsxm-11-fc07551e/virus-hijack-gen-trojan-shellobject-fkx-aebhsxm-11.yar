rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea20d492021c5d5adbd121be75b537e1b3bcbd33785b61b3490250961b750de2"

  strings:
    $s1 = "\\YIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}