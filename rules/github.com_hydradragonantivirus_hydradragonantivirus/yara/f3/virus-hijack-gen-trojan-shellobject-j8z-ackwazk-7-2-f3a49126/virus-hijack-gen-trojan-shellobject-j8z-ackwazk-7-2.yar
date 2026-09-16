rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_aCkwazk_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@aCkwazk_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afe77b1b3182ba7f0e471443e152bec25c8151e0b782f4709a6cfa1b54b0c018"

  strings:
    $s1 = "cHiC O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}