rule Virus_Hijack_GenPack_Backdoor_Hangup_B_229_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_229_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4809f4e851a877fde96003776b3fd891152a58b899d35e878ff6917edd92239d"

  strings:
    $s1 = "LL!This program cannot bedrun in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}