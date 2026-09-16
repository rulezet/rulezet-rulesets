rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_au4JtZd_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@au4JtZd_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58fbdc7a9c826ca46024460e60efbb3329a0c97e2b6af42d4e81e204085d6785"

  strings:
    $s1 = "Discord Not Found" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}