rule VirusShareTrojanLoaderNET6_1_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanLoaderNET6_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fb021494e505cab99ecdfd3cbebfeb3910eaa5380ad952ff4ae6016f4b78f22"

  strings:
    $s1 = "pArK$3" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}