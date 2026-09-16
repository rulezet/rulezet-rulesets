rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64a1c062674fc2b2f4051ee495dd30b61be9fb2159f3c3ca4d61e1e3203ae0c2"

  strings:
    $s1 = "wovore horse" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}