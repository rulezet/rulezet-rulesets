rule Virus_Hijack_Trojan_GenericKDZ_98113_260_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_260_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "593b763166371fc420d05d993df3cc359a71bb90e321422e4cd10d8af10b9513"

  strings:
    $s1 = "R*FLAN " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}