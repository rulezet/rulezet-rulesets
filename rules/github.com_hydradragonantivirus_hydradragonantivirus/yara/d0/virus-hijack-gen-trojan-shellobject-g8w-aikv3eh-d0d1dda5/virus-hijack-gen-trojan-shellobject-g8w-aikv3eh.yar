rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiKV3eh {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiKV3eh.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a862d9b4fa872674d401cca49e11062d92022c7c5f98043fc2c8f01014d26c35"

  strings:
    $s1 = "kSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}