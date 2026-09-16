rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3d456f92467569cfc7ab209792b5c83b7348d06b30b9e787e5da0c0fa298e09"

  strings:
    $s1 = "Zby different names such as reseller, distributor" fullword ascii
    $s2 = "D1F>aUrA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}