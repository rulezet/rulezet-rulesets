rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_20_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_20_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "056d795bd04d3c0df34f15067b976055b57ff1bb9b3bdcccdd0668cf91f2158c"

  strings:
    $s1 = "fEU$fCU|fC]teAT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}