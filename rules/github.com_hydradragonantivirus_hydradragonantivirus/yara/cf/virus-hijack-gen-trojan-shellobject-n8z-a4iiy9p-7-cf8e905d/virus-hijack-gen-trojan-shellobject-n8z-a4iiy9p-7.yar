rule Virus_Hijack_Gen_Trojan_ShellObject_n8Z_a4IIY9p_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.n8Z@a4IIY9p_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92c485038f714880413e794fe6cb28d48c1a2080047d5a9fa762bd17cad9f8d6"

  strings:
    $s1 = "tSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}