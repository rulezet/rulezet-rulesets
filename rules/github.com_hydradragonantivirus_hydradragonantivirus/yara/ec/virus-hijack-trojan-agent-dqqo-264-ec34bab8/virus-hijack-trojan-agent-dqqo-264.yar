rule Virus_Hijack_Trojan_Agent_DQQO_264 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_264.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d99bb8fbb412e4629f68fcbdfb73091bc955b472aabbcc43dc2adc022dd5435"

  strings:
    $s1 = "!functionality of the programs. You have 30 days from the delivery date to evaluate these programs. If you decide to use any" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}