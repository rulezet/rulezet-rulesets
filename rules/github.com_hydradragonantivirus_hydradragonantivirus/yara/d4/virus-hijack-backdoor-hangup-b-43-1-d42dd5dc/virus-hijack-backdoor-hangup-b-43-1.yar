rule Virus_Hijack_Backdoor_Hangup_B_43_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_43_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "964a62bddd85c27d01be3f4dbb9b7aa7e7163f4da9c4d422f3c2bfaf7cc5afbe"

  strings:
    $s1 = " license is the" fullword ascii
    $s2 = "Person: is defined as your employee or" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}