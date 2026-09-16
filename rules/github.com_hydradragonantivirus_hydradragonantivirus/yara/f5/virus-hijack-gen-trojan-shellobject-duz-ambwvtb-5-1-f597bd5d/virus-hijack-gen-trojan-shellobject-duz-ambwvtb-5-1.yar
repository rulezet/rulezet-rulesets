rule Virus_Hijack_Gen_Trojan_ShellObject_DuZ_amBwvTb_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DuZ@amBwvTb_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f192e2834b5e1f9ad9602dd8b59e11c0f15cc6fe5696933e029f9f638ab0a39"

  strings:
    $s1 = "Copyright Hjdhyefe" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}