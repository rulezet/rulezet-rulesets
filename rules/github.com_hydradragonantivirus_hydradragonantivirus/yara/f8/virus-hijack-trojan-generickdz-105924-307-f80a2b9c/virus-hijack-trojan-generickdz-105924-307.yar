rule Virus_Hijack_Trojan_GenericKDZ_105924_307 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_307.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74e41e00365f2616640f180254908d07eed49e7dd94aaf6ad982635876657562"

  strings:
    $s1 = "WeEt;e-t;e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}