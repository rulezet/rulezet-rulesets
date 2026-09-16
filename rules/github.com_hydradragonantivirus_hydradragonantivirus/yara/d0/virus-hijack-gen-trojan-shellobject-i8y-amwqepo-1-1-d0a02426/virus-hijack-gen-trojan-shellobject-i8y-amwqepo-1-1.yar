rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_amWqEpo_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@amWqEpo_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d08c4b8b8a81ec9b7d0f3a286cd5d65ed0f3734ec14db30bc4eb202059b9911"

  strings:
    $s1 = "Firefox and Mozilla Developers; available under the MPL 2 license." fullword ascii
    $s2 = "1Firefox is a Trademark of The Mozilla Foundation." fullword ascii
    $s3 = "<Module>{1598fd0b-39d2-473c-8a03-16f527e4b95f}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}