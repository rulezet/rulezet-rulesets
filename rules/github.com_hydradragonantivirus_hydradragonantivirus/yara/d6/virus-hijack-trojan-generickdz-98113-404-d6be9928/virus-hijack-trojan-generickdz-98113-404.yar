rule Virus_Hijack_Trojan_GenericKDZ_98113_404 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_404.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "534425f90520183a53f8252141db355c70579d5e8cc213efbbb398bf96970ddf"

  strings:
    $s1 = "1n4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}