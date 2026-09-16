rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_690_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_690_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "659965d10004841d09f4795433358ee61b3ef503271787ed6eeebfd3c87e7824"

  strings:
    $s1 = "Qare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}