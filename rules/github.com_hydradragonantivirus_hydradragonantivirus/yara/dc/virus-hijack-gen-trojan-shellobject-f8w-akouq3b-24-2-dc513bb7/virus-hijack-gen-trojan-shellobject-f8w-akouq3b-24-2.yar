rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_24_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_24_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "959c507d6057d63a92924c308f6fca7759db46d611b79fccde24e66c2528a680"

  strings:
    $s1 = "PELT,HlV" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}