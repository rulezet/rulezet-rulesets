rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aeOesjp_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aeOesjp_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b790b25dbbab2dc7bf7e26732828ddde6956d724e45ca123cc7ba8d99131700"

  strings:
    $s1 = "F*GIft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}