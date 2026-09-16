rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20c83d0a14c9bedc12dde679f777e76a13f38d01fce8830d8c549d5dacd56d26"

  strings:
    $s1 = "zfunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}