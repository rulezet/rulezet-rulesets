rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_76 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_76.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f506eb4a42e1dfeb56fc83bc7124c1c63f7f642ce363bc755e375156fe24fe26"

  strings:
    $s1 = "m-Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}