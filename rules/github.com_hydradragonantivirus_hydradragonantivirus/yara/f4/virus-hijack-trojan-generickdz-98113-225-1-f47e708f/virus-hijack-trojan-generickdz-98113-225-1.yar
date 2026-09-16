rule Virus_Hijack_Trojan_GenericKDZ_98113_225_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_225_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80b878aa805ba3a0694e5f8df054d9e10f9db777cb9fb07186faf7c8ec994c33"

  strings:
    $s1 = "RuSK&N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}