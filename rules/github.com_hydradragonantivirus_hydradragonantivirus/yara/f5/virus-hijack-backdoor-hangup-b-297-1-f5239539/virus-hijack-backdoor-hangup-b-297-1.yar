rule Virus_Hijack_Backdoor_Hangup_B_297_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_297_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6007ebadf5e464bf8d825bfc47560b6c2f47da6b21c4eb45180341741ddefd1"

  strings:
    $s1 = "imization_result_': array([0.743" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}