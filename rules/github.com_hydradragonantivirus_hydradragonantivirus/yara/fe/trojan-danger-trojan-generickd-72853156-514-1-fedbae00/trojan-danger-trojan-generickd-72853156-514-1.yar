rule Trojan_Danger_Trojan_GenericKD_72853156_514_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_514_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77f9dbb155f60cef1bcb1c8c4f5926c50c705d789cd7e6811a6ff15d693a32db"

  strings:
    $s1 = "t+ IntegratX with SOAQY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}