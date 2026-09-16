rule Trojan_Danger_Trojan_GenericKD_67269844_54 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_54.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae966da19739c15fd2e078b704272ac379100995013ca2b4cf247935489888c4"

  strings:
    $s1 = "Event Viewer.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}