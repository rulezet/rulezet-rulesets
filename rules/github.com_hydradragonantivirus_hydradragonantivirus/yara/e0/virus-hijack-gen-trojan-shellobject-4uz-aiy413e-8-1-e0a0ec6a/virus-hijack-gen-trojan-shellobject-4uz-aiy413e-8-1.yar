rule Virus_Hijack_Gen_Trojan_ShellObject_4uZ_aiy413e_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.4uZ@aiy413e_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ab8c313793cc805ecadd279bb006023f884c54de8218a029d1d978ee75fa767"

  strings:
    $s1 = "$$Wet3Ny}gUNK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}