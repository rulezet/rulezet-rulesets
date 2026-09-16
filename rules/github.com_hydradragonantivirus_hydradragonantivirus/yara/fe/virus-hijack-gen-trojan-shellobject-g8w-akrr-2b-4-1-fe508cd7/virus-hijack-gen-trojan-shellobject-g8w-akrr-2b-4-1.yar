rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aKrr_2b_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aKrr!2b_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f460406510fc8a6949d0e57290294de860d866f39bd16b4a2b373012c254a98"

  strings:
    $s1 = " The specified file was not found$No help viewer that supports filters" fullword wide
    $s2 = "sicas  Infantis - Confira aqui,  musicas  infantis  para  ..." fullword ascii
    $s3 = "Dragging@\"H" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}