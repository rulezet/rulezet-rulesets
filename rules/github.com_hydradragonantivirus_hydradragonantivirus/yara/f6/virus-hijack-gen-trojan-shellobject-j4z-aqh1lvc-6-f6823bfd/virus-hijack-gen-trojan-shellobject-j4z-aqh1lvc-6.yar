rule Virus_Hijack_Gen_Trojan_ShellObject_j4Z_aqH1LVc_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4cf5d9c5316265e407b61c05010fae0a39a30f14bdb9bc6ce810737c9e44986"

  strings:
    $s1 = "cimust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}