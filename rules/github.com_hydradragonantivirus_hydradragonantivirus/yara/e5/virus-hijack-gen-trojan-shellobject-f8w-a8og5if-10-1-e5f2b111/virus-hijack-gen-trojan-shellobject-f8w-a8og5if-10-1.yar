rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c4bde8a2b945791a699fdb8edb1d7794e8d7af7a5319ebe80b0e9d17874a747"

  strings:
    $s1 = "4***Added ntbvtest@ntdev to D:\\UserMan.ini" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}