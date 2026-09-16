rule Virus_Hijack_Trojan_GenericKDZ_103285_542 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_542.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "036f952db1e9abdb8a4f8278e5907f0c225c76167307018b4aab35ef15af96aa"

  strings:
    $s1 = "QUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}