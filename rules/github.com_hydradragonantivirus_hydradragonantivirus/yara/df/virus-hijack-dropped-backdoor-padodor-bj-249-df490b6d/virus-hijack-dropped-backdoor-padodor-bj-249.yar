rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_249 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_249.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62f38a0441fe946e30a240af2fdf0312e575c4323d6edc3623e1f02413474ad0"

  strings:
    $s1 = "X\"are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}