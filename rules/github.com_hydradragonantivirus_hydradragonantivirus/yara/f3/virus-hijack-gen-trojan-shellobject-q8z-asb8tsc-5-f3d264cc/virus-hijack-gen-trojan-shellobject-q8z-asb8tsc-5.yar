rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aSb8tSc_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aSb8tSc_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1da73bb240f76da4efcf2290dab74a791954dd117827f51fbba9bc2ee3a8123"

  strings:
    $s1 = "^%hOVe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}