rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_672 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_672.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9b9e23819f340d01cc4e303fcf1f8dd3f373965cf20d32eff7d3dfc9153cc93"

  strings:
    $s1 = "3are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}