rule Virus_Hijack_Trojan_GenericKDZ_103285_162 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_162.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edaf1e03a0597de89404b1d8722b0baa2e8bb585b0c22701fc83ec70bdf2d6c4"

  strings:
    $s1 = "QB`gAPO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}