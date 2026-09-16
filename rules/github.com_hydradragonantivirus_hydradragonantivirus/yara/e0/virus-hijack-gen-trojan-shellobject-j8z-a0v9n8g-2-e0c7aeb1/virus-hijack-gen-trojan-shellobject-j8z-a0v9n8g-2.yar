rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_a0V9N8g_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@a0V9N8g_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2e5836d2b4121648fa9dee5c0a7328d8e5a8fe83bdd94745618232bb3a0fa30"

  strings:
    $s1 = "Lby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}