rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea8eb58289eaee98076c9601939661e8984fa3fdbdd7be4322f2d21f4eb79b22"

  strings:
    $s1 = "<Module>{58B61BE3-EFDF-419F-8785-7348790F432F}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}