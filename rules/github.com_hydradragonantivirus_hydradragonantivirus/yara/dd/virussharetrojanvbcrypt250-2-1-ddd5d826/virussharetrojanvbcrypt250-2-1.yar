rule VirusShareTrojanVbCrypt250_2_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanVbCrypt250_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a08ab52c88a11cc72043fd662acec687cfcaeb7c573a8b902b2fb15b81feccf4"

  strings:
    $s1 = "AkrA}0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}