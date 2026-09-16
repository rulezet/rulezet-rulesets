rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_280_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_280_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd3fbacd6ff67cc236ed0dceec305497d048f8efca696b7ac1aff316b221c7ed"

  strings:
    $s1 = "GpLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}