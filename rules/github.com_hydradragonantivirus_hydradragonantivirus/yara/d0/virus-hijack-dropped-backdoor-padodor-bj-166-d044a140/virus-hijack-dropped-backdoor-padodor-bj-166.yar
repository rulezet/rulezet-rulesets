rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_166 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_166.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e3b1c47fb5fbc155198e2b11daa3efbc95cf5a9efddeb3118d07bea43e45c7b"

  strings:
    $s1 = "Labor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}