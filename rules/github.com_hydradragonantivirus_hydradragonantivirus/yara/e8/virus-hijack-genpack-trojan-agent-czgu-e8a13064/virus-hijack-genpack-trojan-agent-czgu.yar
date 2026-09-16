rule Virus_Hijack_GenPack_Trojan_Agent_CZGU {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Trojan.Agent.CZGU.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb12e7bb0204035e575f6bc699772d8a607107fb736c6100374b9859d8342a53"

  strings:
    $s1 = "gram FU" fullword ascii
    $s2 = "Module@1" fullword ascii
    $s3 = "CRITIC" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}