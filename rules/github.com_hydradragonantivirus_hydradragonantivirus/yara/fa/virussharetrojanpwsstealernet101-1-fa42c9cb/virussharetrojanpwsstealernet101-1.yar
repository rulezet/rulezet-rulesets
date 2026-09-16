rule VirusShareTrojanPWSStealerNET101_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSStealerNET101_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18125cc6cd5e88362125b405f2959a70a25267de73188c86c401564ba4418e9e"

  strings:
    $s1 = "V&kEEN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}