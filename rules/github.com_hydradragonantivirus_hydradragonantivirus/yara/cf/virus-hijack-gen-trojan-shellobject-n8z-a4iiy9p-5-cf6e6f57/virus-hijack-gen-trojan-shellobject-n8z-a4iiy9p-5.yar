rule Virus_Hijack_Gen_Trojan_ShellObject_n8Z_a4IIY9p_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.n8Z@a4IIY9p_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52677dbc89b59e447b9d33666f9949a46614566a452d313f303921f806d9d99f"

  strings:
    $s1 = "~Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}