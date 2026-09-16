rule Trojan_Danger_Trojan_GenericKD_72304918_149_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_149_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9176355ca9bac13cf396ec8670feaca01bf28aeb797693278d5f5a7d400950fc"

  strings:
    $s1 = ")!swOm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}