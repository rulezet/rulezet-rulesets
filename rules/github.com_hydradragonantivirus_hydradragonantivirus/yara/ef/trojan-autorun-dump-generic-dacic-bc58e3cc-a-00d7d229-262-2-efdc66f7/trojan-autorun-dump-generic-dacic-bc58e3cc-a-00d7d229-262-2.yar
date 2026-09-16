rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_262_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_262_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5286c6ff4b4e1996c41e7480e073541f880a514c8bc0a8f6b2191a80df71c84e"

  strings:
    $s1 = "Fast Desktop" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}