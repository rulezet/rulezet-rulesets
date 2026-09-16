rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aCV_JGo_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aCV@JGo_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fcd0388c1baabfa67c70fc3dece458cf6f3a218c6f690c262d6629c69556e6b"

  strings:
    $s1 = "V*virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}