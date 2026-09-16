rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_203 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_203.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad706fafc7e313aa718a21e8a0b30be6ce1fdaa3bb19be0579ba03c59a06da2"

  strings:
    $s1 = ";prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}