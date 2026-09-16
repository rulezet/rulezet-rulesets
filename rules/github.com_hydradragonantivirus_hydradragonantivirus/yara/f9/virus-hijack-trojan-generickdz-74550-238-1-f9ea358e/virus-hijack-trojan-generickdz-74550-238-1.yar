rule Virus_Hijack_Trojan_GenericKDZ_74550_238_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_238_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c5832eb10e84f30ea4aeff38ea53fd9a0df954da3ba1c7bf2f2cbf6cf9beb0b"

  strings:
    $s1 = "B'[TREK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}