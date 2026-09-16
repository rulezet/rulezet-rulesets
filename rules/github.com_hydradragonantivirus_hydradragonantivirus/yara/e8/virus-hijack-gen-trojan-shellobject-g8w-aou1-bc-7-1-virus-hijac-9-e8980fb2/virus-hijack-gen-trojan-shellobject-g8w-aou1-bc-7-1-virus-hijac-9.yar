import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOU1_bc_7_1_Virus_Hijac_9 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d13c9ed600e109cf6540800f702eb28921b75c703a68e810bfea63d1989a81d"
    hash2       = "69c67bdda6ae1be885235b7d2d1b99cd9b0711f48bc55dbcca4f45c7eace9f02"

  strings:
    $s1 = "/C ping 127.0.0.1 -n 2 && taskmgr && " fullword wide
    $s2 = "/C ping 127.0.0.1 -n 2 && \"" fullword wide
    $s3 = "Lespeed Technology Ltd.1 0" fullword ascii
    $s4 = "Lespeed Technology Ltd.0" fullword ascii
    $s5 = "wore&3" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (all of them)
    ) or (all of them)
}