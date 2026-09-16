rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aCkwazk_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9826b8e26422a67314127ac2f1ee5fb9b7038d98e5e82e735b2189c43f22cc8"

  strings:
    $s1 = ":#gNaR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}