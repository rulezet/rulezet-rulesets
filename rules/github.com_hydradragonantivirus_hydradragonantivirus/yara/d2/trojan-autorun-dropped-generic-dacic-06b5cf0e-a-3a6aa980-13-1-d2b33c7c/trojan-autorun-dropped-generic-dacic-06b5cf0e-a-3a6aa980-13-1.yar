rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_13_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e34f12914cc95793bab9f36e3f61470df6a7c7147315de834b744351cad3874f"

  strings:
    $s1 = "Copyright (C) buidgre" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}