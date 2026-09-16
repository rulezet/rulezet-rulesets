rule Virus_Hijack_Trojan_Agent_DQQO_67 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_67.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7be2bb374de0e3a3e5220f05dde999886aaf8a72b876579b628c0cd9f64bfcff"

  strings:
    $s1 = "6whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}