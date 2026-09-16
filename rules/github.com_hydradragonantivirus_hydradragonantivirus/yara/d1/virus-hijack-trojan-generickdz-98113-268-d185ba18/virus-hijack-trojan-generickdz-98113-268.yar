rule Virus_Hijack_Trojan_GenericKDZ_98113_268 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_268.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fcf94fcc98e859c8cf18b253cc3ae1e238ff935c75e393ea9a1ff8aafb8c8e7"

  strings:
    $s1 = "{4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}