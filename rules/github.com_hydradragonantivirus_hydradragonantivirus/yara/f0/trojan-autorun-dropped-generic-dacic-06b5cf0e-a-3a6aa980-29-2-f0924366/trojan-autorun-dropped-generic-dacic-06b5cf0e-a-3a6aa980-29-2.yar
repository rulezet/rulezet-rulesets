rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_29_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_29_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd8917276c3d7c626bafa2bb1c415c7199a6bdae1171dcdc75bde0be8f1b5dc9"

  strings:
    $s1 = "^]STuT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}