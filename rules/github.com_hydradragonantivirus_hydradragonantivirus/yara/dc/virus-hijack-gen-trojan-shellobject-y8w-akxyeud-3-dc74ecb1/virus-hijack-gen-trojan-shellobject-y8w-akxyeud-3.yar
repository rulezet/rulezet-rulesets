rule Virus_Hijack_Gen_Trojan_ShellObject_y8W_aKXYEud_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.y8W@aKXYEud_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11a5add1d24a00ad163f426669b56ea64fbf17625f9fe1715f068f896907a694"

  strings:
    $s1 = "?ToLl>g$q{" fullword ascii
    $s2 = "TaLd>$$q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}