rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_98_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_98_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5cec2e723d3963bef9e41b6330e5c9a913bf5a227d9b77c18d2c3f7656f1596"

  strings:
    $s1 = "gaff:g;hminnBoCpuqvvJwKx}y~~R" fullword ascii
    $s2 = "qdg8d==l8lo@lEEt@twHtMM|H|" fullword ascii
    $s3 = "beef`eh" fullword ascii
    $s4 = "DAMAGE:" fullword ascii
    $s5 = "ghklp9ee98==:AmmA@EEBIuuIHMMJQ}}QPUURY" fullword ascii
    $s6 = "turn}!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}