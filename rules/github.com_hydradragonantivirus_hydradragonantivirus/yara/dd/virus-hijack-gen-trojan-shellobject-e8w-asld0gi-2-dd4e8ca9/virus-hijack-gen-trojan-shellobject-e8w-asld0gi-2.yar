rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f3a006661b44902733816b07f59587223e22fdf37998e548691648dc0b13c99"

  strings:
    $s1 = "this agreement, as well as all sums remaining unpaid for programs ordered and/or services received under this agreeme`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}