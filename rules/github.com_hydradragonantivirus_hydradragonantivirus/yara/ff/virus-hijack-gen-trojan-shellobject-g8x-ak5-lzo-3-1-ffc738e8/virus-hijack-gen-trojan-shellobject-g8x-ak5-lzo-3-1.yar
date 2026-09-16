rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9b225c44afce02800e1e7cfca5311c8fcdaee9fd6922e146b91b9b2b23770f4"

  strings:
    $s1 = "Divisible" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}