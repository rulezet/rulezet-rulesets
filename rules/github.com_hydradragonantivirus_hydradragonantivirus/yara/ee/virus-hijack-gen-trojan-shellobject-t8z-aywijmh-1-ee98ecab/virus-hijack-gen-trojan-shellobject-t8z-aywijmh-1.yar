rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_ayWIjmh_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@ayWIjmh_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "953b7f0ebce5c41211d8cf91343a7f89a1c26c8a29e3f0f51e7bfe359f2a2035"

  strings:
    $s1 = "9nyour order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}