rule Virus_Hijack_Trojan_GenericKDZ_103285_625 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_625.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ec075d5b46d76b68f94ae6aa3a5dd923a6571ec10dce7a5caf456474f7a8b69"

  strings:
    $s1 = "7&University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}