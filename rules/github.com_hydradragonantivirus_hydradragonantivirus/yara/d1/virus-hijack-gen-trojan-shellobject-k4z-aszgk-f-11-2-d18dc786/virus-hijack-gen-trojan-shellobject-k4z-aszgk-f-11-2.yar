rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5239c40d39d022e0be7c70b6ac0380a7ba06c6a7639dae18fe0902437a196e77"

  strings:
    $s1 = "fRAT>S" fullword ascii
    $s2 = "!pTvector<T> too long" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}