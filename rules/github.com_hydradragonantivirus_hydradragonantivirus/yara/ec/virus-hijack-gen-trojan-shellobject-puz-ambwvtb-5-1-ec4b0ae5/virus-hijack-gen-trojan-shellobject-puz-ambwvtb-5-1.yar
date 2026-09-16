rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f79145d9e166bfac7b032746f53641c9e4746b78f8e56cb26b81dbabca75c5ea"

  strings:
    $s1 = "taHIN'2" fullword ascii
    $s2 = ">mILA." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}