rule Virus_Hijack_Gen_Trojan_ShellObject_pyZ_aeWgNZc_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aeWgNZc_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5918242f731f1f9cb550d97e722aa91b324b34b41e5c4d199e60a583e8f9c61"

  strings:
    $s1 = "STEP<C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}