rule Virus_Hijack_Trojan_GenericKDZ_74550_318_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_318_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154ca09a25f4c8bf750b109708135fac15cc74102885bf572a0c207327699c00"

  strings:
    $s1 = "v)mAsA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}