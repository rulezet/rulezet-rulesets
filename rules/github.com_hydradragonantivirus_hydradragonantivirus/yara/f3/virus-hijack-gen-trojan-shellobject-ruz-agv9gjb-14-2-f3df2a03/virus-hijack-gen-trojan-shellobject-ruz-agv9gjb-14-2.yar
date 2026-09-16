rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9b69c9f6c861c6bbdeb50bd5f584f5691841c1db4a7ef01741df32f4adc8783"

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