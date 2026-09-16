rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aCEmdoo_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aCEmdoo_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ac9afa1e6cc9352964fc71be2cb1cbf60c4965d81248d5a9125aed3907e7c85"

  strings:
    $s1 = "?$SifT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}