rule Virus_Hijack_Backdoor_Hangup_B_263 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_263.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29c1e2dc68fae519a459a6ed2011871db37ce1992abd2d8581f1f1f5ace8fac7"

  strings:
    $s1 = "BooT$o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}