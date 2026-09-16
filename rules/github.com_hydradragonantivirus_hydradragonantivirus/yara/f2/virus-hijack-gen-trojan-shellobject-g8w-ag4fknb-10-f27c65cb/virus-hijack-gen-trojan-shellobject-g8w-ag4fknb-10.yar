rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aG4fkNb_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aG4fkNb_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "532179f93b49d47b92479c75312b1a5833fe1d9986d4204d3bf46e7bbc3d8889"

  strings:
    $s1 = "1]pulK;," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}