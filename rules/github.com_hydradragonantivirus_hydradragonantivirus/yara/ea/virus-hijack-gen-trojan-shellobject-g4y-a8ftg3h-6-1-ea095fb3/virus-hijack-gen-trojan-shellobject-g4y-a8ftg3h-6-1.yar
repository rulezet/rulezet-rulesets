rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_a8fTg3h_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@a8fTg3h_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41d0877241259d82620220f4e529a8dade875153692dfc127fa7b8172ebfd3bb"

  strings:
    $s1 = ",blas " fullword ascii
    $s2 = "lOOd*W" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}