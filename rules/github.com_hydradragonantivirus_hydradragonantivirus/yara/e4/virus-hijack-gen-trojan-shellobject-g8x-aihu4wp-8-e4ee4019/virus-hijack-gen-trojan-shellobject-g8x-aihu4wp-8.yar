rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4310b14ff7a695f986734ec173306b4b4ba0c4257b909eecb025e4a72dafb775"

  strings:
    $s1 = "IyWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}