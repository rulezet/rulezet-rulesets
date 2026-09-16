rule Virus_Hijack_Trojan_GenericKDZ_105924_298_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_298_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "420e8641668ae533e4a3b88d76a7c5fdbc2a9440461b99f9a261ae77876194ed"

  strings:
    $s1 = "<!loWA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}