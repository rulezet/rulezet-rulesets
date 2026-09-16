rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "055059d95e4ce01c68c907d91aaccd5e0bf79117338c1a3946cc742b967f8904"

  strings:
    $s1 = "actU; " fullword ascii
    $s2 = "aunt,v" fullword ascii
    $s3 = "buhR>6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}