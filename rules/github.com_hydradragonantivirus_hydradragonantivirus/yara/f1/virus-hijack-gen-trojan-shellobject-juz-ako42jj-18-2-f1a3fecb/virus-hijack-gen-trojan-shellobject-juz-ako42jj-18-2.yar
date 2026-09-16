rule Virus_Hijack_Gen_Trojan_ShellObject_juZ_aKo42Jj_18_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_18_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d541361dfb3369d4f3c9effb0c751fc8e91b2293d6a922dff918f32fd6d03023"

  strings:
    $s1 = "oofY#<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}