rule Virus_Hijack_Trojan_GenericKDZ_105921_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a3c1c1e155482cf068877d33cca9e2c7f72405b0aa52c2eb2d9491f967fe195"

  strings:
    $s1 = "72013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}