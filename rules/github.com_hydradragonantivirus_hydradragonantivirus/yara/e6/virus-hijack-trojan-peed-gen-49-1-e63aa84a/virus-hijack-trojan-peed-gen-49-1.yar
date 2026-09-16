rule Virus_Hijack_Trojan_Peed_Gen_49_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_49_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d35cb7d724f2606381ce66ab3836a237c44038589107f6e66a66412d472cb298"

  strings:
    $s1 = "d<MeRE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}