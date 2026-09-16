rule Trojan_Autorun_Trojan_GenericKD_72517131_12_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bb4ca9f9af07019d1db7d36a45dec3a0af46a26a1c417c0bbe5c8aa27748f23"

  strings:
    $s1 = "-OUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}