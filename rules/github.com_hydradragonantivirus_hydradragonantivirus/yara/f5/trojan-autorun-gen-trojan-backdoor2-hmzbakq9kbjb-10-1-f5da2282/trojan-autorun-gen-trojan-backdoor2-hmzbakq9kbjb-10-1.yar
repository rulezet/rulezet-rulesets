rule Trojan_Autorun_Gen_Trojan_Backdoor2_hmZbaKq9kbjb_10_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.hmZbaKq9kbjb_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88bcf1d9c5041be6a6a7a2ce4c860634b92e9dfa5e35ff48ad2493f2391c624d"

  strings:
    $s1 = "Gfunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}