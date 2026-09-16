rule Virus_Hijack_Gen_Trojan_ShellObject_LzZ_aWELKOd_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.LzZ@aWELKOd_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74b6923c71298f2875480c87ca0ad7bc5458c8e6b25d57b8b9384021fd0c0158"

  strings:
    $s1 = "BALI:'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}