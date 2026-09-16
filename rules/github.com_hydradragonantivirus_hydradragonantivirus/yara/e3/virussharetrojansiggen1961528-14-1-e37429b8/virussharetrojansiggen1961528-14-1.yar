rule VirusShareTrojanSiggen1961528_14_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1961528_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ade170d43b102f5e2910339388771eea6b75308124d4bfdb840672d522ad4596"

  strings:
    $s1 = "aSSI&:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}