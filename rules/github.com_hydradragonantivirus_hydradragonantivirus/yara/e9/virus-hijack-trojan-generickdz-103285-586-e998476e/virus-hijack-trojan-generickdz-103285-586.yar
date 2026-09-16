rule Virus_Hijack_Trojan_GenericKDZ_103285_586 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_586.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b324809d1a7f78c532a368bbdb321a511f321e345e9d9d0eefe32458f1e8c197"

  strings:
    $s1 = "CUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}