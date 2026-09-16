rule Virus_Infector_Win32_Neshta_A {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Neshta.A.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d17027039d1db86b6a61156685426359e5a0b2ef24165d8b5c57d5ce4bf50769"

  strings:
    $s1 = "Shell (Isolated) - ENU" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}