rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69baf87f060a037ef41c5a56fd2159530c69254ed85e14c980c69a9a31b30d12"

  strings:
    $s1 = "k:finD" fullword ascii
    $s2 = "R%atEs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}