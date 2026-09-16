rule Virus_Hijack_GenPack_Backdoor_Hangup_B_37 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_37.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "850687948ca3402cd3ee810e7d5352f5633677d27176276f296da8423d69f751"

  strings:
    $s1 = ":Cyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}