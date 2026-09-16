rule Virus_Hijack_Trojan_GenericKDZ_103285_419_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_419_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9ad7c622054dc0a408ec3146300468d2b64279c8f084b2ded3b4f3a15c963d6"

  strings:
    $s1 = ",Reference Viewing Condition in IEC6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}