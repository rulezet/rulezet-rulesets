rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5de2f8945ce08cc412d5aa644aa715edaf4d9d51b517339bcb487895fa346fff"

  strings:
    $s1 = "<assets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}