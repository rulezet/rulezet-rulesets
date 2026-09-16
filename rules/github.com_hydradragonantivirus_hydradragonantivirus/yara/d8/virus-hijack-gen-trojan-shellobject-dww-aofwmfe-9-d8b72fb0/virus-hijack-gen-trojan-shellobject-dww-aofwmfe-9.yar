rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "243e942dbe94157e70a4414c0f01d1f0803717a2231b7e8bea03e62da4266ce6"

  strings:
    $s1 = "include more than one version, su`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}