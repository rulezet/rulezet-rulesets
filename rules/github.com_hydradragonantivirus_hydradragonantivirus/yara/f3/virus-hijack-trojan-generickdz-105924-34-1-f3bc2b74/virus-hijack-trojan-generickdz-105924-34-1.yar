rule Virus_Hijack_Trojan_GenericKDZ_105924_34_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_34_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "799bf9acd9b0ca72165ef73deee2b013729d95019e38ca32df5abb802812e695"

  strings:
    $s1 = "v;pooH,'y5" fullword ascii
    $s2 = "{`miSt" fullword ascii
    $s3 = "STAm`]" fullword ascii
    $s4 = "LOrA:n" fullword ascii
    $s5 = "W}gull" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}