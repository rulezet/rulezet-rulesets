rule Trojan_Autorun_Trojan_GenericKDZ_94847_341_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_341_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "257a46287ac43b1dac9548117c79a3012249921a7a35617ee547f0a80a920dec"

  strings:
    $s1 = "7whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}