rule Virus_Hijack_Gen_Trojan_ShellObject_oyZ_aeWgNZc_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oyZ@aeWgNZc_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe5dfc686b0e4abdfecb598a62827e914f003635128cfa1abbd9ab79e659261b"

  strings:
    $s1 = "Shell Infrastructure Host" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}