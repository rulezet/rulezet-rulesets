rule Trojan_Autorun_Trojan_GenericKDZ_95048_6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95048_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4a729ae80f2d392cdc4f9b68315e4555e27f767fd4b52267111d0867429eb5f"

  strings:
    $s1 = "]MProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}