rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_163 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_163.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dd82fb77ce038599a62576c4e67389c37b8b071373e7a7964944c178f994f2e"

  strings:
    $s1 = ")and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}