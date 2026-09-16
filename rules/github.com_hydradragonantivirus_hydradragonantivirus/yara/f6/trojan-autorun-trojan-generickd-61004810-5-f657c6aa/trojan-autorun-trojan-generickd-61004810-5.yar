rule Trojan_Autorun_Trojan_GenericKD_61004810_5 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.61004810_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97aa02ad230a0fdacbab0cb04ab9308cf9cabcae53d223c1b7804345befa7e6e"

  strings:
    $s1 = "WErt,b%" fullword ascii
    $s2 = ".4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}