rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_amgke_k_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@amgke!k_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b5e1f00cb31130977b7496942a3819894ac36caea2690349f04561212b391d4"

  strings:
    $s1 = "VLC media player 2.1.3" fullword wide
    $s2 = "    --palette=PALETTE    specify the colors to use when --color is active" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}