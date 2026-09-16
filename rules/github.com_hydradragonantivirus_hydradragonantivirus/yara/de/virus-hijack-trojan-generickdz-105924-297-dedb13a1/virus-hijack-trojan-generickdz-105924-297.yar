rule Virus_Hijack_Trojan_GenericKDZ_105924_297 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_297.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b57f67f65d91c63f985ff2ef6ff662b0ac4fe78a857bf62bd29dfe855ae32e27"

  strings:
    $s1 = "32-$/gtb-omom`mx7&q`lalo&p,{+x" fullword ascii
    $s2 = "c7|r1l'jj cgy0&n}lalo&p,{+x" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}