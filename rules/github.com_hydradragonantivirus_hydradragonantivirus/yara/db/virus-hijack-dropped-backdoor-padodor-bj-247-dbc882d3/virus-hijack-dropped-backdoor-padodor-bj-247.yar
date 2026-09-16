rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_247 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_247.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02a9bd90ff035231ab326a9f9a76aa18621139a8e7eae7123227689b44029ba9"

  strings:
    $s1 = "eare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}