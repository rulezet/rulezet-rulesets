rule Virus_Hijack_Trojan_GenericKDZ_98113_133_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_133_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80b53574651a1ffb35bc45187e779fce2859ade6c1cc7c60cb472b57b44f2a02"

  strings:
    $s1 = "luRA#Vly!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}