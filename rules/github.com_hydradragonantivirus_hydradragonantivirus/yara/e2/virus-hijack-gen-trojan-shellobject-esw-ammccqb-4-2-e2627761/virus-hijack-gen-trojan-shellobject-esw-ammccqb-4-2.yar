rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f39c9bf80808d9dec00433a7a83359d16c3dfce108e60f07a360b7887ff4b01d"

  strings:
    $s1 = "untaken" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}