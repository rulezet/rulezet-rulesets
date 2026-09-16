rule Virus_Danger_Gen_Trojan_ShellObject_f0W_a0DbbBi_2 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.f0W@a0DbbBi_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5b4dad5d4d6e200330ab10b3389cb5de3050e4ca11cfaecf82be95a50a92a4f"

  strings:
    $s1 = "access to the Oracle iSupport program may not be licensed as Employee Users, but must be licensed as `" fullword ascii
    $s2 = "OofY<d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}