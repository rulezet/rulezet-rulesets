rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_25 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26c6e5bc9bb84a1ad52902af64297afea4df4b357930b88976da37c26e89704d"

  strings:
    $s1 = "ejghhd:6e;<7?lB>mCD?GtJFuKLGO|RN}STOW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}