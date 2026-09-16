rule Virus_Hijack_Trojan_GenericKDZ_105924_593 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_593.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6941c9600a436fe0c34e3dbbb0bb91e3421da111d6ec318e3aa6f438cfc935c0"

  strings:
    $s1 = "}Veer>0e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}