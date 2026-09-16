rule Virus_Hijack_Trojan_GenericKDZ_103285_669 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_669.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f45383cee9811e1d0320d44e086d591defeeda36d9140c1d8a217ee58348ace2"

  strings:
    $s1 = "dWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}