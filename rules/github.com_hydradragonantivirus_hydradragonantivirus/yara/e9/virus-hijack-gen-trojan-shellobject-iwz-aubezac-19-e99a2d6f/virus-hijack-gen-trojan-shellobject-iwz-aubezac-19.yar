rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66fd34f3c1d44d54bb943400e36be185f979cdd527a7a85528f4b76bba07b2b8"

  strings:
    $s1 = "(jakO>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}