rule Virus_Hijack_Trojan_GenericKDZ_79663_107_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_107_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18e1b444849c73f0d4877eea974f8260a53d05887cefe92fd0661c3a7305ff7b"

  strings:
    $s1 = "l)Jell" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}