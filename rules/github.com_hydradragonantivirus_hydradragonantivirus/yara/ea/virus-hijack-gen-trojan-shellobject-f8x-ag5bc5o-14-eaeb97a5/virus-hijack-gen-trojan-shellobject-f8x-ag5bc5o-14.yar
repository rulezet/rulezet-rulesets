rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3394fb1affd7373a6c76af5b10e9f9b6766ece01d480715616518c82c977dfc"

  strings:
    $s1 = "kuBA?1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}