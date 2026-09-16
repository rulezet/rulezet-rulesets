rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_564 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_564.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de1ecac6a86ac9252c6db68abfab87e3e6c871e6a22ca2a11f5cce4269bb2719"

  strings:
    $s1 = "Labor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}