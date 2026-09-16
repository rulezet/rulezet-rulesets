rule Trojan_Autorun_Trojan_GenericKD_72517131_217_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_217_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "636ac2f24a91434ad3c9644dd447a1be7b27858461c11bb6a1f456c2bcb15ad5"

  strings:
    $s1 = "LUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}