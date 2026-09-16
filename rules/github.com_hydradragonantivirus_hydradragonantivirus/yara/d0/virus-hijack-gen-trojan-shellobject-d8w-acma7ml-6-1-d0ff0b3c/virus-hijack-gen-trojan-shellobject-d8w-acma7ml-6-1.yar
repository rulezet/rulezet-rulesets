rule Virus_Hijack_Gen_Trojan_ShellObject_D8W_aCma7ml_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.D8W@aCma7ml_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e3e02cb5c10b6750ff084fb1556c97f48c1e4756255336a190cfc43d5bf6cc6"

  strings:
    $s1 = "Visible in Windows API, but not in MFT or directory index." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}