rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cf105622dfa0956ac99282750987681eea4f9020209842c8347d9a5f734cc42"

  strings:
    $s1 = "W(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "W(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}