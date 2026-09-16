rule Trojan_Autorun_Trojan_GenericKDZ_94847_410_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_410_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9f4c09d093d070feb7106690c33741059b39dea0b4db39577524fd07cdc6c8d"

  strings:
    $s1 = "Dwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}