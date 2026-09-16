rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_687_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_687_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c02391b23d8aa59d506b4ad584fd5c7c496fc2901e8dba34c7b77aa40e80b2c4"

  strings:
    $s1 = "$and hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii
    $s2 = "the same degree of care to safeguard the confidentiality of the TRMs as you exercise to safeguard the confidenti`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}