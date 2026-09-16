rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_au0WBJh_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@au0WBJh_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1902fa9e8fdf6c46b50c3d63732c31e99cacd74a8bacdd8ae8175f0c9936ee6"

  strings:
    $s1 = "/Forders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}