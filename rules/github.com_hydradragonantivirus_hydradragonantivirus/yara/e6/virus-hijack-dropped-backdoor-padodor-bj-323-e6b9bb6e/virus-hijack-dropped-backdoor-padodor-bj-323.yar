rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_323 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_323.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "861659ea4b9a7caf15498e982f777cf7ecc95d2b8f9a76b1195c23c2048dd0f7"

  strings:
    $s1 = "Labor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}