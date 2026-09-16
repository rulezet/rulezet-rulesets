rule Virus_Hijack_Gen_Trojan_ShellObject_pzZ_aCEmdoo_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pzZ@aCEmdoo_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9002706a29af742d42e253d7096ebb38d62c5ae433f733ceb484a5c628a958fb"

  strings:
    $s1 = "*epHa?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}