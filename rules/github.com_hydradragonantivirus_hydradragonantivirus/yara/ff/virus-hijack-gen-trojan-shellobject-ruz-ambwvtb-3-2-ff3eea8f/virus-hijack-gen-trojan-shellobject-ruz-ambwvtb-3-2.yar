rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd5755761b8014f817c4f1336adbe90ab06db741dbcff5e308f3938d65a7ce20"

  strings:
    $s1 = "kernel)V6" fullword ascii
    $s2 = "p@gram {!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}