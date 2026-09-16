rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2f8185526be9356a3a77a00a0a69828dc4e5cf482dbec756c881570b6c6de36"

  strings:
    $s1 = "J(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "J(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}