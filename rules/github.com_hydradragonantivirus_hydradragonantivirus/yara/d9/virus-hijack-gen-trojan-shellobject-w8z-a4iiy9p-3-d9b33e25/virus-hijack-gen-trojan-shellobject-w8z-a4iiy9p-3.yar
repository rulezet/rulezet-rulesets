rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_a4IIY9p_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@a4IIY9p_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d248c29416ac6b76a04c6d65d12dfd3362ebcbc668847fb8c6668edd8b44ed5"

  strings:
    $s1 = ":Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}