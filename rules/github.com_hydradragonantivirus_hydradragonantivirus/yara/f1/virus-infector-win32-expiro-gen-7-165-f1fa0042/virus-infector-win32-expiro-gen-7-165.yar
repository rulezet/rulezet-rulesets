rule Virus_Infector_Win32_Expiro_Gen_7_165 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_165.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce747f43400e783ec92a5e735cd3f3470a521b22e96a2efb685fc955f19e114b"

  strings:
    $s1 = "*epHa?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}