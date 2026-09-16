rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b22b809cd5214abd60fed19068298392cf62e1cdf45d0557f4db9b42b1766183"

  strings:
    $s1 = "BIT COMPUTER CO., LTD.0" fullword ascii
    $s2 = "BIT COMPUTER CO., LTD.1" fullword ascii
    $s3 = "Action@QA" fullword ascii
    $s4 = "Font<ZC" fullword ascii
    $s5 = "Management Team10" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}