rule Virus_Hijack_Trojan_GenericKDZ_105924_561_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_561_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44a04aebf1d9de007c5cd225e3c43b52ff26b7c1cc3c3169606c2a895327c8b0"

  strings:
    $s1 = "eddO' " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}