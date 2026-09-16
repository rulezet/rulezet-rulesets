rule VirusShareTrojanSiggen827287_3 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen827287_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbe7eee5f2cc32b619fd3620ab5000a77786e59c29b2c635b4cc4b82e8c7c9b5"

  strings:
    $s1 = "F_controlfp_s(((void *)0), 0x00010000, 0x00030000)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}