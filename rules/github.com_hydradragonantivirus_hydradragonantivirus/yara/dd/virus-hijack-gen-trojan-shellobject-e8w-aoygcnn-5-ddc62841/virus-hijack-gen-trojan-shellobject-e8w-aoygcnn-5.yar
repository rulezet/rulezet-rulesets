rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81cf1f564d4961cc5ce2688e8be94af2934c4f3588db0079b0d5daa20aab07ee"

  strings:
    $s1 = "Bhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}