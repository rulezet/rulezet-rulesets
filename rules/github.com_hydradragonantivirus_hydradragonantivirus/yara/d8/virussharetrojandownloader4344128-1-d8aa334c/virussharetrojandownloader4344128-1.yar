rule VirusShareTrojanDownLoader4344128_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4344128_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c470befb36e1720865dc049427bcd1e212db58bbb71e32a99efc85f5c83b5162"

  strings:
    $s1 = "Bowerlet" fullword wide
    $s2 = "Shisham" fullword ascii
    $s3 = "Nonrenewal" fullword ascii
    $s4 = "Edgeman" fullword ascii
    $s5 = "Glycolytic" fullword wide
    $s6 = "Syncarpous" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}