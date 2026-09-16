rule Virus_Hijack_Trojan_GenericKDZ_98388_31_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd533b86e473b480b51ebb6b54279057e93226a7eaef7d0357de61559815caa5"

  strings:
    $s1 = "ULla \\" fullword ascii
    $s2 = "peoN>F" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}