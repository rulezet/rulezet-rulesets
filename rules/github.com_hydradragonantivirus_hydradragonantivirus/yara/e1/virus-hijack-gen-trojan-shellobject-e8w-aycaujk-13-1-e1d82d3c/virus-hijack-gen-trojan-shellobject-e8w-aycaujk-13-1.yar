rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "832b135f35112040fb5bdc292aeb42186247c4802ea700e671d363cd036eecf5"

  strings:
    $s1 = "aluminium " fullword wide
    $s2 = " gluttonous" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}