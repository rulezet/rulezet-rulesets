rule Virus_Hijack_Gen_Trojan_ShellObject_DuZ_amBwvTb_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DuZ@amBwvTb_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c43521ebab7fa18ba044deb5a61358083fb01c4ea455f9ad30a6f2111fa698c5"

  strings:
    $s1 = "Copyright Hjdhyefe" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}