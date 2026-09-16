rule Virus_Hijack_Trojan_GenericKDZ_74550_48 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_48.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "128fbd760b53c450908d71baae8db707d3402173b7112d8627409cc79dac99cf"

  strings:
    $s1 = "jimP%i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}