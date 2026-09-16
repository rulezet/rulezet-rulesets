rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_a0V9N8g_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@a0V9N8g_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca9968a3936eefbfe115d6c7d7eb4d522f353c120e1824f1ae04880cf97caeb4"

  strings:
    $s1 = "ASby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}