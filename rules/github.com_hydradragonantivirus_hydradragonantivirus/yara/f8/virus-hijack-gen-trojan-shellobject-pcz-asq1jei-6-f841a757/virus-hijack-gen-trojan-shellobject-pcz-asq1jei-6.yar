rule Virus_Hijack_Gen_Trojan_ShellObject_PCZ_aSQ1jei_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aSQ1jei_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56780ee5bc16fa5317e57903659996d44724b29855765a1ac535afa6747814c4"

  strings:
    $s1 = "cITE?j70y-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}