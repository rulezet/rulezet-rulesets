rule VirusShareTrojanSiggen2814921_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen2814921_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eecd633aa202e8c3e4920606811a9ce25f52112faf2e84faaf4fe7df4da5602d"

  strings:
    $s1 = "your ps is start in the lamer system for all user" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}