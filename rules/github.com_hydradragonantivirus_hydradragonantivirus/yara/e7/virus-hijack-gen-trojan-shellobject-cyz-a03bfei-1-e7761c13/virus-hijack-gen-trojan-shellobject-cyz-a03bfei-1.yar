rule Virus_Hijack_Gen_Trojan_ShellObject_CyZ_a03BfEi_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.CyZ@a03BfEi_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98d0a889610836c292b8b66203616dd26d6e1fe60d2428359b0b2645f01f6c9b"

  strings:
    $s1 = "eNdYMA" fullword ascii
    $s2 = "meLd,e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}