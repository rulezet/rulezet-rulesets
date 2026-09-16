rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_236_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_236_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed53a9baa4291185d48c495074770cb91134ef8305196050013aabd9ee6720b4"

  strings:
    $s1 = "B(format != NULL)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}