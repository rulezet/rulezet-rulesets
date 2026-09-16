rule Virus_Hijack_Backdoor_Hangup_B_306_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_306_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89f4279021e120d980d21064a7f57b15f5fe3632032b6879d26a1e6885178381"

  strings:
    $s1 = "7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}