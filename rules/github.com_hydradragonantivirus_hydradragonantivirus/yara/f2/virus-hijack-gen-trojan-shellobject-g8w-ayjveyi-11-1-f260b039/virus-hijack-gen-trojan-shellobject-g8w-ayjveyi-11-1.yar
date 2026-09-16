rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7fbdde76bab0f383599f36a2f7e18a3a4b0659e4a92e11255eb28af8ef4e101"

  strings:
    $s1 = "Divulsion" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}