rule Virus_Hijack_Trojan_GenericKDZ_105924_449_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_449_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c8d1058e7ba17b18bd8e346361b0afb125e747eae06406888b1d225c323faa4"

  strings:
    $s1 = "sHorE " fullword ascii
    $s2 = "nAnE:@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}