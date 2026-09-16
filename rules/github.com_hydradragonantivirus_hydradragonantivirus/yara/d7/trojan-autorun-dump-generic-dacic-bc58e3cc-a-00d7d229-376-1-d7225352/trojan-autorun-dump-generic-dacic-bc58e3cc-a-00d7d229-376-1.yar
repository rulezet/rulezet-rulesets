rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_376_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_376_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af88494bd6ea12057a178757a0f5c37f6a43f18169b75dd9ffb847a786798118"

  strings:
    $s1 = "h!Labor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}