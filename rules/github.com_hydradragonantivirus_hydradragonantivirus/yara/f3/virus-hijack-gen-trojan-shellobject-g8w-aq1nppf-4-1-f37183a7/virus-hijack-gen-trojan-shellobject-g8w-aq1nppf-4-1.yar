rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aq1NpPf_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aq1NpPf_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69c7be25c1fcf080687223c06be8294a18d67eb69db0619193904a6ba9b42103"

  strings:
    $s1 = "  Install" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}