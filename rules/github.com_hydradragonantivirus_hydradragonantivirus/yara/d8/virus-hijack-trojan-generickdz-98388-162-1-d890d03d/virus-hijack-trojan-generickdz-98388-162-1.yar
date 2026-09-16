rule Virus_Hijack_Trojan_GenericKDZ_98388_162_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_162_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14c4b72f10ae745d311072dd8a558569ba22cceee311e47d387634760fb9f04f"

  strings:
    $s1 = "e>PART" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}