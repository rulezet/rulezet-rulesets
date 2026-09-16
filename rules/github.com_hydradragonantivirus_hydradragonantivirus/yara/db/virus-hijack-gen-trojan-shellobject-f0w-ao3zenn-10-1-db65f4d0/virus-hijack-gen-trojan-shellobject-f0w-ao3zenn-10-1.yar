rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea308f752d728aa237e6294b789f3dcbd92f0843a967aa9c5a8ec26bb2282405"

  strings:
    $s1 = "***Added ntbvtest@ntdev to D:\\UserMan.ini" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}