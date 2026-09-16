rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_238_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_238_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e11570106ff7d4d571778c7cfef195e32855b9a5f33c2c2eeae59a9f767bace"

  strings:
    $s1 = "uOracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}