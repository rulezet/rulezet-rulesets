rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_472_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_472_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cea49837925b433d68ed7300b39e9c445e59ef1dbcd321d21b78adef8bb637ed"

  strings:
    $s1 = "y6active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}