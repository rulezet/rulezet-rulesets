rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf345abbfeb4bd4b80332299e5f0c7e026787d6c375b152ee3cd421b9790233a"

  strings:
    $s1 = "Fneed dictionary" fullword ascii
    $s2 = "About Naver" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}