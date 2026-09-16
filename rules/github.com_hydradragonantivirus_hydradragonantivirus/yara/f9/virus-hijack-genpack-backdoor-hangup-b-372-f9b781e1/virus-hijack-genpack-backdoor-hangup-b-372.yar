rule Virus_Hijack_GenPack_Backdoor_Hangup_B_372 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_372.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39f0f8c57b7970c0ac968dff46ebde89a59f941c39766c6d7996bf4c8f44effe"

  strings:
    $s1 = "_Xyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}