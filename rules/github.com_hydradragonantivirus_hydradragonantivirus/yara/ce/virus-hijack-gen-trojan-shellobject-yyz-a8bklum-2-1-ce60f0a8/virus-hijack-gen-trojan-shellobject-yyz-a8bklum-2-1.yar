rule Virus_Hijack_Gen_Trojan_ShellObject_yyZ_a8BkLUm_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.yyZ@a8BkLUm_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5610b526727be6aff64b93dcdd01a40e0acaed77a8471c9712e21a648cf4cf1b"

  strings:
    $s1 = "018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}