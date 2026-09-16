rule Trojan_Autorun_Gen_Trojan_Backdoor2_HmZbaKq9kbjb_11_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.HmZbaKq9kbjb_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdda1855c807da731e6197a9f20c42cdd967cfe9a5ed1fb8bd0cc6d52dabfa0b"

  strings:
    $s1 = "/whundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}