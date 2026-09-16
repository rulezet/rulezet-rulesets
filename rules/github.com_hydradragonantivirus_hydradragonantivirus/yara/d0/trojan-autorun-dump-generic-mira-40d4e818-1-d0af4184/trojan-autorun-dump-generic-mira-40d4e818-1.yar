rule Trojan_Autorun_Dump_Generic_Mira_40D4E818_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Mira.40D4E818_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e5e5c8299a07317dedb803b042fb7e073ac6b4201bfd9717cdea3242ea6ce53"

  strings:
    $s1 = "mgto be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}