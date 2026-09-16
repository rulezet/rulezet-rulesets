rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d08f143a4b0e6370eedc6abac59d9ea0f729d9ad73f01cb7591529bf9982f70"

  strings:
    $s1 = "Xj}TOtY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}