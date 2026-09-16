rule Virus_Hijack_GenPack_Backdoor_Hangup_B_352_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_352_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "061f3d3fd022bff43022a09e5f0e5e355df95ff201e49e0ce5229927b55a0044"

  strings:
    $s1 = "LL!This program cannot bedrun in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}