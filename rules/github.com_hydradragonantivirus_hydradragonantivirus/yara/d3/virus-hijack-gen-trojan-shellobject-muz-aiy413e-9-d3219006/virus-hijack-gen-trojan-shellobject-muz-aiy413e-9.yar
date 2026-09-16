rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_aiy413e_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@aiy413e_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d86bc8801011b043c2a80dfcc404b219103d9e646119f8cbbeee5873a03995ea"

  strings:
    $s1 = "oDuM,^t" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}