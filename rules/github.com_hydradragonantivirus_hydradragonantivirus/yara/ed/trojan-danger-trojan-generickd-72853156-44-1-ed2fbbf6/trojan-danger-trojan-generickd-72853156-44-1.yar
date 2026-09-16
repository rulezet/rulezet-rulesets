rule Trojan_Danger_Trojan_GenericKD_72853156_44_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_44_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "166afe2a60da2cfbc2a5950e92f02640fd87ae61aae5b1b2710ac28e52d859b4"

  strings:
    $s1 = "A9k>BilE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}