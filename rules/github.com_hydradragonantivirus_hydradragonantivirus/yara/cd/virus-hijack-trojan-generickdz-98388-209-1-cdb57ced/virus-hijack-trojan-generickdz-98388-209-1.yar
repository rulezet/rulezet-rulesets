rule Virus_Hijack_Trojan_GenericKDZ_98388_209_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_209_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2358a16134784a4b7b337b67f705d4e1592cd72554b49772dd1268557f4e799d"

  strings:
    $s1 = "8`peSt<e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}