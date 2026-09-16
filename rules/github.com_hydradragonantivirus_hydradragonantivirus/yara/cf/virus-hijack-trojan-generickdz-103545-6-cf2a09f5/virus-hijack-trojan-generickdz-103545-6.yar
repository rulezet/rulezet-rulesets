rule Virus_Hijack_Trojan_GenericKDZ_103545_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7fcb5dccbefec1c16300bf442487ed7eeca22e2b1e7aaf0d0102147370e14aa"

  strings:
    $s1 = "www.oracle.com/education/oln/index.html, and may be updated by Oracle from time to time with`" fullword ascii
    $s2 = "0Lsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}