rule Virus_Hijack_Gen_Trojan_ShellObject_oSZ_aaT6Wyj_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oSZ@aaT6Wyj_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3477b365046f29ae86c30c59bbce69f3a1413262bcf325e6738d1ada3590232c"

  strings:
    $s1 = "4whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}