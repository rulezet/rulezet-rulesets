rule Virus_Hijack_Gen_Trojan_ShellObject_YCZ_auWluQ_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.YCZ@auWluQ_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeb805d114825a7ba7a55f3fb33df5d3d0d407c0bbcc8cdf84e15365cd42a364"

  strings:
    $s1 = "Gong{Rl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}