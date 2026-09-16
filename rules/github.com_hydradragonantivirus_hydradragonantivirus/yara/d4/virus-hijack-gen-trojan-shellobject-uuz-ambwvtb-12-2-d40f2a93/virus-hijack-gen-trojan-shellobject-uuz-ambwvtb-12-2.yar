rule Virus_Hijack_Gen_Trojan_ShellObject_uuZ_amBwvTb_12_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uuZ@amBwvTb_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d3779168b3bf2797b9e1546f590a94b8bd06ea28169f47a9981266fc100d537"

  strings:
    $s1 = "11:58:07 AMam cannot be run in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}