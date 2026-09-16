rule Virus_Sysbot_Dump_Generic_Dialer_BEBD122F_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BEBD122F_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ea1a5089f6a018424752fbd79f67d595e2871cfd0c0c77e097422ce1b312c8a"

  strings:
    $s1 = "GOUt%>" fullword ascii
    $s2 = "<]lean" fullword ascii
    $s3 = "6xO`ANAy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}