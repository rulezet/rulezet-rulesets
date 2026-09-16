rule Virus_Hijack_Trojan_GenericKDZ_98388_134_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_134_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b74be1b3e547b50de46620fd087c8adab96bc7b437d7436747e4a3436c535206"

  strings:
    $s1 = "gOTe<P" fullword ascii
    $s2 = "}SiDY<s" fullword ascii
    $s3 = "MUNj:," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}