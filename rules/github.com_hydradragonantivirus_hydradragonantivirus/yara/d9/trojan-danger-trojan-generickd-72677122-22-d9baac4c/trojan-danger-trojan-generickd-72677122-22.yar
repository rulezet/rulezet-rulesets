rule Trojan_Danger_Trojan_GenericKD_72677122_22 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "009f13f8e96bc316f01cc69b029a652253e795f13f3bcd461792cd94d5f7028f"

  strings:
    $s1 = "Event Viewer.lnk" fullword ascii
    $s2 = "TRap?<RRRRRRnS__R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}