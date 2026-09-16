rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_168_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_168_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "175374e42456b82bd6830afafa91c6fbc6deb76124affcc45483843cc07947c2"

  strings:
    $s1 = "Diare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}