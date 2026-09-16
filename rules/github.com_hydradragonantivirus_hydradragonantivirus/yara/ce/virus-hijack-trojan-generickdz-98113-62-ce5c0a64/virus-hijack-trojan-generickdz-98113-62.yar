rule Virus_Hijack_Trojan_GenericKDZ_98113_62 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_62.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fc9216e32d41bb583ebe1bd102a0103564152070b17fa5fce4eb267bf6482c8"

  strings:
    $s1 = "Z4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}