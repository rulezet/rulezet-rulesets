rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_100_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_100_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5e03caf49c31ada6808b911bb9eac05fee4480ccd480eef36b244d84c89bd4c"

  strings:
    $s1 = "a(are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}