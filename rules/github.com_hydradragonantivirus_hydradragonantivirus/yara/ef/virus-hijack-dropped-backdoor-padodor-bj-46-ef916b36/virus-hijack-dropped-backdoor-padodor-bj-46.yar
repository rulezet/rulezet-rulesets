rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_46 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_46.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea102ae56a9814f8a03af211a21a5d9d9167c1045dcdcf4381c021b6da397f92"

  strings:
    $s1 = "fprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}