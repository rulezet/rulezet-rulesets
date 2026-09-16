rule Virus_Hijack_Trojan_GenericKDZ_103285_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f4caedb7e07b2632c378094b63c0ca3434fcf819eb194953c531c8cb980a88a"

  strings:
    $s1 = "INSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}