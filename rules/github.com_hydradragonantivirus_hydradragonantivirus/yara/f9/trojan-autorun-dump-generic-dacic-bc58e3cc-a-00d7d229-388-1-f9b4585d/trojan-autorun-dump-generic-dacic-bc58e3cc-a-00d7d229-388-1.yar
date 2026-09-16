rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_388_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_388_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfc7abed7865d9e2f5b8f9e924dcaeacf4376feda9e27c593eb71de8004d5272"

  strings:
    $s1 = "PMicrosoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}