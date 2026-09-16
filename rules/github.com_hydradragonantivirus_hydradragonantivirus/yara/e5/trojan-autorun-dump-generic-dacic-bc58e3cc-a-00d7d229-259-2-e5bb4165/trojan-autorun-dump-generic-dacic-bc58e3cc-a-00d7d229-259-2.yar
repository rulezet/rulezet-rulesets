rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_259_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_259_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56de996f04b0e3d25ae4b788de37df9c7fe9c2899b632b6908937e336d5fdbb7"

  strings:
    $s1 = "Discord Link :  v1.0.0-custom" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}