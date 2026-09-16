rule Virus_Infector_Win32_Expiro_Gen_7_31 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90e75be787f40daa6c2b1777483d3234bd619b65b7830ecb85007705d47af4cc"

  strings:
    $s1 = "dARE#p" fullword ascii
    $s2 = "\"MuZZ%Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}