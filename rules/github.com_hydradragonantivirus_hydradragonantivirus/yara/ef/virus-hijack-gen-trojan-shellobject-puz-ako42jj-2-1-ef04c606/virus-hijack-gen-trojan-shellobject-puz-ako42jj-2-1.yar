rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_aKo42Jj_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "165d78e96cfc29a050249be2df44551c5cbea2868c3179bf143c3d786f67ef58"

  strings:
    $s1 = "RiFf)O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}