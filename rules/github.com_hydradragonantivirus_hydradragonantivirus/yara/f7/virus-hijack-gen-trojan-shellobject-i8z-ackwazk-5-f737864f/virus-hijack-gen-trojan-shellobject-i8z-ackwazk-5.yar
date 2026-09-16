rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aCkwazk_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aCkwazk_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a37b6df8aa5d051a5c5a55e00a4f699b3e6ecd39fc402492addddd480cddecf7"

  strings:
    $s1 = ".by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}