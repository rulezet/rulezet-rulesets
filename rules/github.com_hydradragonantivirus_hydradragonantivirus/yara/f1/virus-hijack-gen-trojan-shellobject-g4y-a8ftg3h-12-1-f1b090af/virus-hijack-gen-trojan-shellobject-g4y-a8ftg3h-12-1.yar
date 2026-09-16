rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_a8fTg3h_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@a8fTg3h_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d4874500301ed318f95b56f12b2ba23096df92c9d43789c7405367421f964b8"

  strings:
    $s1 = "soPe{Q?f:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}