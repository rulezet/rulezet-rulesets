rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aS0V58e_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aS0V58e_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a30b0597855718482be8739a36c64916a38ed9f51f1a410288b0ba3ef39889af"

  strings:
    $s1 = "bAiN%0H" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}