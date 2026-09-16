rule Trojan_Danger_Trojan_GenericKD_67166905_228_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_228_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59919e5231b8eca0b1843116bb7a225f2bcc409b11a2103b0b06afe6228cca4a"

  strings:
    $s1 = "]University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}