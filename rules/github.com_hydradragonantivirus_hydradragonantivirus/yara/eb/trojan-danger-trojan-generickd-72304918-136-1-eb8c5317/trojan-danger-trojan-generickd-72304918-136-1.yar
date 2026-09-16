rule Trojan_Danger_Trojan_GenericKD_72304918_136_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_136_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "784c2c05971a481b3f49873b809f3e4593076b01f26c9447faad7bff9087be08"

  strings:
    $s1 = "|Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}