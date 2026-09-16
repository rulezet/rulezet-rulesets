rule Virus_Hijack_Gen_Trojan_ShellObject_GyZ_ayMBdto_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.GyZ@ayMBdto_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "533ef80003452db34345c347e4cca8c7fc097ca30f5a11da92b53249367a9c80"

  strings:
    $s1 = "nm#Ya$Beak \\j*6_/k7Dge0Yuol" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}