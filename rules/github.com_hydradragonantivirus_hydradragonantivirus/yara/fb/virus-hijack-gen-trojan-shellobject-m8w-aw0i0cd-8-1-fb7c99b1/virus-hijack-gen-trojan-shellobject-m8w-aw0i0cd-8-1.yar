rule Virus_Hijack_Gen_Trojan_ShellObject_m8W_aW0I0Cd_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8W@aW0I0Cd_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38e44dee659a735c2e651a88158aa98c2c61a4d5a23f26495b1acb2713f6492c"

  strings:
    $s1 = "brAw #." fullword ascii
    $s2 = "aNSa(d/" fullword ascii
    $s3 = "fy<iiwi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}