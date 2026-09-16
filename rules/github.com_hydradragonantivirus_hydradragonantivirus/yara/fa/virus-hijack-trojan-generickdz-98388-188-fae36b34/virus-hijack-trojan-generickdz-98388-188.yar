rule Virus_Hijack_Trojan_GenericKDZ_98388_188 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_188.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46767d02821483dcbdc7c476684cab2345bc40a488008d26a5f282ce61965a20"

  strings:
    $s1 = "program and/or materials resulting from services (or direct product thereof) will be exported,`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}