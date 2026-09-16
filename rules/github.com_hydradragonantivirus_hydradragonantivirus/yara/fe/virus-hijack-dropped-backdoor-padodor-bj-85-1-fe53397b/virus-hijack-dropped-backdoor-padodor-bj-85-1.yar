rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_85_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_85_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bb146791c4c6ce4d7c5fdcf4c62684ce0aa1919e2be9892938cbf2e0986bdce"

  strings:
    $s1 = "Copyright Dejhi" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}