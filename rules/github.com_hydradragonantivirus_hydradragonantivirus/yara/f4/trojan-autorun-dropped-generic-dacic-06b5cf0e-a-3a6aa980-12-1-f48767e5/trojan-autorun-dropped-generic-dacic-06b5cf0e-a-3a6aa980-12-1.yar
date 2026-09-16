rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_12_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1079c13cb46ec3a063002fa6ca537506184aba60719ee0c5b8cab6e75ad44788"

  strings:
    $s1 = "Copyright (C) buidgre" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}