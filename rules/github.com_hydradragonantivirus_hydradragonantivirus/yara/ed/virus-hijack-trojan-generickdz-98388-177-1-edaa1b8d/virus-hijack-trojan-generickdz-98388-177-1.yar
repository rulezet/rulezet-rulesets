rule Virus_Hijack_Trojan_GenericKDZ_98388_177_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_177_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a52a87a20a2d1cdd18e5a9e6cfdc0791a9c55a0e7ad74758b605fe3cad2fc500"

  strings:
    $s1 = "gOaf}#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}