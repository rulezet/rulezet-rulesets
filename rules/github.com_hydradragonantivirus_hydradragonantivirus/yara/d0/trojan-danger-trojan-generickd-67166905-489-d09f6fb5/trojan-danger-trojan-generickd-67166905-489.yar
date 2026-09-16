rule Trojan_Danger_Trojan_GenericKD_67166905_489 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_489.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68a888e472a047ed67d8ffadb292e23189e067b0f9a735928ba5a5aa46a6fbbb"

  strings:
    $s1 = "agreements or representations, written or oral, regarding such programs and/or service`" fullword ascii
    $s2 = "wremainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}