rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aCkwazk_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d38249eeeb59baa040b97e78e6289666f124a69deb645602f5eb35e265957535"

  strings:
    $s1 = "oBEY]k/" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}