rule Virus_Hijack_Trojan_GenericKDZ_98113_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7f713f7be9c0197e4a7f8d062e263118e16d4ae8d0701430c0d897ae38108bc"

  strings:
    $s1 = "HEmp;\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}