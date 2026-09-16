rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ef4933bdde147b1407c00a349a0b399c56f78986fc8969c5cbdb91523f13e02"

  strings:
    $s1 = "National Instruments Domain Service" fullword ascii
    $s2 = "Provides a domain server for NI security." fullword ascii
    $s3 = "NweSer Document" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}