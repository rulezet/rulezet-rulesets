rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4be145eeca6b9d845726e064c33272c3c54210ac3eef4e183443e7bbd67884b"

  strings:
    $s1 = "VWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}