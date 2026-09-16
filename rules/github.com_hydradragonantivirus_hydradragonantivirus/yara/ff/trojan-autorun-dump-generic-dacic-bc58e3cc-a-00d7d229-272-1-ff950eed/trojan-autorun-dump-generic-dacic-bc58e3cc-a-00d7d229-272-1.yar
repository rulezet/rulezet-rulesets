rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_272_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_272_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19ab046b6fc49e38e677054053edb87e0a7c12b6fc1721d21b432e87ca28102f"

  strings:
    $s1 = ";Sare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}