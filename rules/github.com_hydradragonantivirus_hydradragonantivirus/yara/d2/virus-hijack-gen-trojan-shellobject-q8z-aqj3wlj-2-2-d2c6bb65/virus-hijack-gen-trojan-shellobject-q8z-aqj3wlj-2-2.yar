rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aqj3wLj_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aqj3wLj_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39081bb82d3b6854e2aa564744011cba56ef262e8523b98f1580467d65b19266"

  strings:
    $s1 = "n#welK" fullword ascii
    $s2 = "':deRe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}