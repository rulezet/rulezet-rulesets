rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e377f31774bfcd9277fdfd9ca6592a86d45fb215264593dbe79b7d30d7d6928f"

  strings:
    $s1 = "+q(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = "+q(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}