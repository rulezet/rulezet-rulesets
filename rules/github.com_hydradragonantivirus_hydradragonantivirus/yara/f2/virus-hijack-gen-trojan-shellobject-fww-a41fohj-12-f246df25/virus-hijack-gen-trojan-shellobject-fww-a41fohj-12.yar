rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cce550e43433fade1bf8eb963469738f28dcee4badadf2bbb4650fde346de24"

  strings:
    $s1 = "h:(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = "h:(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}