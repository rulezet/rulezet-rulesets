rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_89_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_89_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ffb15f7acc2480c69b73d9d88465aa8ab15f2bfafd786a9374a3bbcc8ec6c17"

  strings:
    $s1 = "s_prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}