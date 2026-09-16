rule Virus_Hijack_Trojan_GenericKDZ_98113_262 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_262.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2aa2590ca9e69292fb5b371992aa407019434179b127679ec514f787bed2a66a"

  strings:
    $s1 = "74. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}