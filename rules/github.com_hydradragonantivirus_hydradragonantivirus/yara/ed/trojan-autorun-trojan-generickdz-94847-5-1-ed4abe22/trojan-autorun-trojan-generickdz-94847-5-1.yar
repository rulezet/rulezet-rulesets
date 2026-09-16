rule Trojan_Autorun_Trojan_GenericKDZ_94847_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d67260b322b099f2451c389be86e333d0f2910c03cb049fcab7454f8bb7885c5"

  strings:
    $s1 = "fmIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}