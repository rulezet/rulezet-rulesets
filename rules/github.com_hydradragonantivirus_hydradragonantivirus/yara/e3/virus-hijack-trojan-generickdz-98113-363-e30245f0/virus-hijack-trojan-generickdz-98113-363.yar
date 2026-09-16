rule Virus_Hijack_Trojan_GenericKDZ_98113_363 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_363.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc9e1ae8acf076aebb5482e76725881e8e964702ea4453dc38135b0e72136bed"

  strings:
    $s1 = ">4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}