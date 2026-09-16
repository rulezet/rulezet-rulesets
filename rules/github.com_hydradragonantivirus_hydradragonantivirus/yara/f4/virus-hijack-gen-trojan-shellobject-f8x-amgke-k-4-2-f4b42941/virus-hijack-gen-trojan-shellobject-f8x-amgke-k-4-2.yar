rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_amgke_k_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@amgke!k_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cdc916d683411a7cdeb48f12086beecd2083340e28e7285710a82eb7bea4a04"

  strings:
    $s1 = "Determining Windows version" fullword wide
    $s2 = "Trying to load SPP based on Windows version" fullword wide
    $s3 = "Spp loading result" fullword wide
    $s4 = "AutoIt v3 Setup" fullword wide
    $s5 = "(c)1999-2018 Jonathan Bennett & AutoIt Team" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}