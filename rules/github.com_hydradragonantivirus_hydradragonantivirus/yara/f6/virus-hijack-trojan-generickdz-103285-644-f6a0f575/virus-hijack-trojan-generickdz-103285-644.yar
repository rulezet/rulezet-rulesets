rule Virus_Hijack_Trojan_GenericKDZ_103285_644 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_644.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02dd4add6bfd62af144216de9891a029f531431f44aa42e76c2340a76a7711e0"

  strings:
    $s1 = "Qvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}