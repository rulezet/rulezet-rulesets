rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_amgke_k_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@amgke!k_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "593b75e53bce4dcf2685fb5174b0f7c9ba52ab4eda416f227bc0a59a796d9e43"

  strings:
    $s1 = "Could not open regis" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}