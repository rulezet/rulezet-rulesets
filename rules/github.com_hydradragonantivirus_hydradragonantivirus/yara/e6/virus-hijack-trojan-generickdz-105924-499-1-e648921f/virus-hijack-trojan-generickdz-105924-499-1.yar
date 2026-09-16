rule Virus_Hijack_Trojan_GenericKDZ_105924_499_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_499_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e313c1cc59c35808129cd9e6c63cc898fddbfcb852f7f937b490ed9eafddfcf0"

  strings:
    $s1 = "TiLEr:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}