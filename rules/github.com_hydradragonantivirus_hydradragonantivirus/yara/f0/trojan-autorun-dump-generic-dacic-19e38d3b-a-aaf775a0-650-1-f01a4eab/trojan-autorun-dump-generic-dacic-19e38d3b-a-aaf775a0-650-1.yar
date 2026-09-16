rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_650_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_650_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e14e25b8fbc6b4bcab5a3928d8aab982e2cdd46d5329281640098958cf437c4"

  strings:
    $s1 = "lprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}