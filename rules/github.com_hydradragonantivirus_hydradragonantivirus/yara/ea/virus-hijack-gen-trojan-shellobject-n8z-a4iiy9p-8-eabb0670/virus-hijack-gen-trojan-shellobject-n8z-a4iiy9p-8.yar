rule Virus_Hijack_Gen_Trojan_ShellObject_n8Z_a4IIY9p_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.n8Z@a4IIY9p_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a94fdb9ee9d99ad3f95ebdecbad1094eb7c1146c97b0b5ab0b6234cec08cf54"

  strings:
    $s1 = "uSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}