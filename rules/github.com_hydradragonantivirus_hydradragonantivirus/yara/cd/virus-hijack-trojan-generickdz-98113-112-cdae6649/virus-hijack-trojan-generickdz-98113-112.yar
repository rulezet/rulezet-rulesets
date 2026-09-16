rule Virus_Hijack_Trojan_GenericKDZ_98113_112 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_112.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "819459e2a932020e268c6b66f35746fe67bdf3e6f8c48b8fcb199811890cc92a"

  strings:
    $s1 = "/4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}