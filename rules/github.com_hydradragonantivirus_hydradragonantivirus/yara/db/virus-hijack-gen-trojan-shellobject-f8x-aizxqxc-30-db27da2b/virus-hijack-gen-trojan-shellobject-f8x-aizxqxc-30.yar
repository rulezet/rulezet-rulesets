rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_30 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_30.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdf7ff99b6f2c12c141e1e4b0da95f189a0e4fa816281856386f509b7c571ac8"

  strings:
    $s1 = ".S.h|'6s``4`b'%`ai)u/e#!}r(!fifE@Tfl`c#/" fullword ascii
    $s2 = "iProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}