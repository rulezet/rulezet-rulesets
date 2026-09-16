rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94245dc568b406e55955aeb81dd8ac71f0721346a8e7896d4b0dfafe44809213"

  strings:
    $s1 = "Bruntime error " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}