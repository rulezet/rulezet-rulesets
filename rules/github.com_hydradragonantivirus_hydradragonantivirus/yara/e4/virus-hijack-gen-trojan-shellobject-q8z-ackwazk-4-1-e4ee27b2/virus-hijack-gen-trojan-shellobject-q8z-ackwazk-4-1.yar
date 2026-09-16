rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aCkwazk_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "999d0fc507fd7a7dd8e9643877e9402616161fa1806e495c495f50d1454fbf5a"

  strings:
    $s1 = "?aLBA'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}