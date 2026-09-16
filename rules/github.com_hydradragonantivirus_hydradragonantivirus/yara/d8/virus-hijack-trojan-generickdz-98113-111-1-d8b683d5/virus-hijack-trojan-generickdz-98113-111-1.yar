rule Virus_Hijack_Trojan_GenericKDZ_98113_111_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_111_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fee2a0669a2e4da5cdb976c3d01aa5c269876418e012b96eab1be8074a50426"

  strings:
    $s1 = "_|`NOse" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}