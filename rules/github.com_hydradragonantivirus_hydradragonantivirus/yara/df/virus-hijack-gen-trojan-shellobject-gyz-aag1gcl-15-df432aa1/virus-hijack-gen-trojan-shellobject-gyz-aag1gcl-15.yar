rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aag1Gcl_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aag1Gcl_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c11c8cc775adf90e505dbe1952a87091498a4cf6898e396631b69abb66e68f11"

  strings:
    $s1 = "Galvanizer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}