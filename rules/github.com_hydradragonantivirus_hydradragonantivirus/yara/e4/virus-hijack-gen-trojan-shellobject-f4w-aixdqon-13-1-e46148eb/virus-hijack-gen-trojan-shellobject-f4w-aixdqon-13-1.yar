rule Virus_Hijack_Gen_Trojan_ShellObject_f4W_aixDqOn_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51a0499c9fae246b8c74b700f6757e71096d9c88a37853a1dac89cbab56fe1aa"

  strings:
    $s1 = "[Default Services]" fullword ascii
    $s2 = "MSFAX XP=Fax Mail Transport" fullword ascii
    $s3 = "PR_PROVIDER_DISPLAY=Fax Mail Transport" fullword ascii
    $s4 = "PR_DISPLAY_NAME=Fax Mail Transport" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}