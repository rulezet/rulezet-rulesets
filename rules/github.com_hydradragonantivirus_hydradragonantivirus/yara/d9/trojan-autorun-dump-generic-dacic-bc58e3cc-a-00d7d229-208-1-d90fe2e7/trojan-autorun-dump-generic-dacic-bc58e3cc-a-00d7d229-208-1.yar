rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_208_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_208_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8790b1170c8acb7a4a0eeac0477186f85dc4ccd72ce294c087f9ff75148c885"

  strings:
    $s1 = ";!are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}