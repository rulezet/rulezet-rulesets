rule Trojan_Autorun_Gen_Trojan_Backdoor2_FmZbaKq9kbjb_9_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.FmZbaKq9kbjb_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47eafdb4a3df93fef0db3f42cb7d1ae62c076dbbfbddfdac65b22bc40461b4ac"

  strings:
    $s1 = "Sby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}