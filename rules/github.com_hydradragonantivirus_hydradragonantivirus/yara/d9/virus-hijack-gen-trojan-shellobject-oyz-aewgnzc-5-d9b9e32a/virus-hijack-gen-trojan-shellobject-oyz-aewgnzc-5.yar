rule Virus_Hijack_Gen_Trojan_ShellObject_oyZ_aeWgNZc_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oyZ@aeWgNZc_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cb940100139cbc35e8a7d4c4a271565d97187171a73a0ea5411d3709bd1d81d"

  strings:
    $s1 = "[+]Got the address to write 0x%x" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}