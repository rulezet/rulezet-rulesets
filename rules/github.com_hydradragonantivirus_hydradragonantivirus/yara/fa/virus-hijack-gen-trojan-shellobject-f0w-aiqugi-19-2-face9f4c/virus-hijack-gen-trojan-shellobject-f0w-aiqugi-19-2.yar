rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_19_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_19_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c03c5e1a08e28b3e57c6d109739c452ce95c68703497681ed85de7ea82df6fe"

  strings:
    $s1 = "sLW!PETarY" fullword ascii
    $s2 = "LW!PESa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}