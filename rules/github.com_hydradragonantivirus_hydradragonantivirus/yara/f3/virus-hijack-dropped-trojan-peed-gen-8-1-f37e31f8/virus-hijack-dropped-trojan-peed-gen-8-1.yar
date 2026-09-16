rule Virus_Hijack_Dropped_Trojan_Peed_Gen_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Trojan.Peed.Gen_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2c528bae1c923f4d28aceb35043b340f5653157102535ea5d5900fcf11e2983"

  strings:
    $s1 = "phototypist" fullword wide
    $s2 = "knopped" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}