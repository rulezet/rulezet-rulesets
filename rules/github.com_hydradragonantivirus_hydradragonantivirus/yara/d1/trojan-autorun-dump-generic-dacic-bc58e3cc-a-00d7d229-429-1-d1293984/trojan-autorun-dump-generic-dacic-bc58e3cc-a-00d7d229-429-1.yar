rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_429_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_429_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9565cda717bce293b35f7b0359a313842ac79a12e2b91ed7423e972d59623f03"

  strings:
    $s1 = "CMicrosoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}