rule Trojan_Danger_Trojan_GenericKD_72853156_524_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_524_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fe3dc74535d9fccf31ac6badc7ea6b4af65780df7b7e10050d6947f2e6cb0b6"

  strings:
    $s1 = "^OLE initialization b nbm  gh ailed.  Make sure that the OLE libraries are the correct version." fullword wide
    $s2 = "Termin%1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}