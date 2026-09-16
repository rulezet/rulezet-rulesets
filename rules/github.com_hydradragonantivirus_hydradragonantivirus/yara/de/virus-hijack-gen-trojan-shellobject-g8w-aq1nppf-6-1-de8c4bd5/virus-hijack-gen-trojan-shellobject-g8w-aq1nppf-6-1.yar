rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aq1NpPf_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aq1NpPf_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "798eaad2990e34aa8090217b93fdda517e076fcfa64d9157002cdc5c0d24b6ca"

  strings:
    $s1 = "Compote" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}