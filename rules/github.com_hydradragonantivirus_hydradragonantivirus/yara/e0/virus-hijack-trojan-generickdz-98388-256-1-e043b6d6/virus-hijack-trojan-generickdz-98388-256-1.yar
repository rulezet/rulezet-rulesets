rule Virus_Hijack_Trojan_GenericKDZ_98388_256_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_256_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5791ce0047b1146cc9ef23f4e029f288dc76e701c54f65bfd85034e08eae920d"

  strings:
    $s1 = "huLl>I#" fullword ascii
    $s2 = "ElsE e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}