rule Virus_Hijack_Gen_Trojan_ShellObject_g0W_a4_lcVd_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03647645fd70ac2a2cfcc6d6b52d2f289c00c0ad391883d4be400067c486299c"

  strings:
    $s1 = "r!Wauf" fullword ascii
    $s2 = "Z@bASh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}