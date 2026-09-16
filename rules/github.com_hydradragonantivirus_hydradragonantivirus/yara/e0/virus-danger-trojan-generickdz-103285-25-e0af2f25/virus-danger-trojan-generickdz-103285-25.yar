rule Virus_Danger_Trojan_GenericKDZ_103285_25 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed571319574dc7e9aae34a4f9ae79ebb72060a8cbee580b8b96ac7fb545d021a"

  strings:
    $s1 = "BeaST&~]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}