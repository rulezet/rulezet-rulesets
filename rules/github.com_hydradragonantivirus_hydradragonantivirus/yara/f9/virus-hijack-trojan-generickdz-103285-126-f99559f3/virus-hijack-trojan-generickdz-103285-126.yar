rule Virus_Hijack_Trojan_GenericKDZ_103285_126 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_126.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5037171a8a5d7aa135b499007acf7cedbe6e9a7980cc8c7cdcb184792339876"

  strings:
    $s1 = "If you have a dispute with Oracle or if you wish to provide a notice under the `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}