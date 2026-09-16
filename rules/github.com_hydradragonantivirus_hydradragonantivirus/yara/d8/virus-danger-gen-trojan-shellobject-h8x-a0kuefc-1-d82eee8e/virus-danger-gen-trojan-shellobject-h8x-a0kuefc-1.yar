rule Virus_Danger_Gen_Trojan_ShellObject_h8X_a0kuefc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.h8X@a0kuefc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "079953c78fe45cb1dab7d39debc215b86ade32a42ddee61750c9c1409ca16f36"

  strings:
    $s1 = "0virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}