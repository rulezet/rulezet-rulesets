rule Virus_Hijack_Gen_Trojan_ShellObject_DuZ_amBwvTb_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DuZ@amBwvTb_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "908e807005077d31a50a6330df474dda6477d18e9b6c333507f71df769b9cd8c"

  strings:
    $s1 = "~;awee" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}