rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_220_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_220_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92fcf8a5096e83dea0dcb77251f22c06da713ad6082a22bd07ef1756e23ab924"

  strings:
    $s1 = "Current(GK" fullword ascii
    $s2 = "Count,~I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}