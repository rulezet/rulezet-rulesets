rule Trojan_Autorun_Trojan_GenericKDZ_94847_237_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_237_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa0a93b403fe57380f64e093d912f8acafd37ae46f340230c733d1fdcb2e6efd"

  strings:
    $s1 = ";whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}