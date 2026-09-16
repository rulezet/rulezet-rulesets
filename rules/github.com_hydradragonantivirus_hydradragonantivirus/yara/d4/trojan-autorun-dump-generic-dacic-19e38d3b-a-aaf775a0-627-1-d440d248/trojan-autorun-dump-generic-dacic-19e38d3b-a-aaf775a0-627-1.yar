rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_627_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_627_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bf76f292659ec3080a0cb813441cb157322bec1fcf9c2f0fb2367b89a2afa8e"

  strings:
    $s1 = "]and services at the list price in effect at the " fullword ascii
    $s2 = "infringement claim could have been avoided by`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}