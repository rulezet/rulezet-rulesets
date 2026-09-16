rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "375417e72df903aef4ca25d3c379229c3ad6b93bc73c4d6282ca765bf9bdbf3f"

  strings:
    $s1 = "c6(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = "c6(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}