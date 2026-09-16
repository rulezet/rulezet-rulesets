rule Virus_Hijack_Gen_Trojan_ShellObject_m8W_aW0I0Cd_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8W@aW0I0Cd_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abee25861f48f1f7abd69009b36e814fe3fae5ec5d112ec9fc3915aaa4bf58c9"

  strings:
    $s1 = "pErT$>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}