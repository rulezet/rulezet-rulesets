rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_a0a9m9p_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6719828924879076ae51b1ab744ecc0fb9e62bbd5de3c43d1933039917475bea"

  strings:
    $s1 = "BSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}