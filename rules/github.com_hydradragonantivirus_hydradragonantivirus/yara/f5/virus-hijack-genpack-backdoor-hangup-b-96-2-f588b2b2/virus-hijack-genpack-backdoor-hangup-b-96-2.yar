rule Virus_Hijack_GenPack_Backdoor_Hangup_B_96_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_96_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "355b2e4926f94a8909f10bc2b72d2983d62b428e07928b72c3fda4d67a8a8b30"

  strings:
    $s1 = "p!akrA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}