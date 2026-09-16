rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5c02197ba5024b3edf41a201a5fe22f0801f87fdf52235c6d6002a92ce5f2ed"

  strings:
    $s1 = "A%weEL" fullword ascii
    $s2 = "&COtE*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}