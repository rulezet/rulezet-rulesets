rule Virus_Hijack_Gen_Trojan_ShellObject_CwZ_amBwvTb_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.CwZ@amBwvTb_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf85cf25a8b5e68c3ea1cb3fb07501aedea66967a4b5d3abbb74bf4df48deb38"

  strings:
    $s1 = ">?NiDe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}