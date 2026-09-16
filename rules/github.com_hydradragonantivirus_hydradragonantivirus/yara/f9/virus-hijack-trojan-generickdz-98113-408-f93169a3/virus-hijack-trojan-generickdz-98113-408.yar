rule Virus_Hijack_Trojan_GenericKDZ_98113_408 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_408.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acad9ffac042a830be515736c04e1373c1856e9ed6d351817eb801893dfece1c"

  strings:
    $s1 = "BY4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}