rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aqA82Sk_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqA82Sk_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a4cb247f8ec8a9c1476c084d4ec58a75798754e904d3cacc92f6acfd0513db6"

  strings:
    $s1 = "_CIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii
    $s2 = "sHor):\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}