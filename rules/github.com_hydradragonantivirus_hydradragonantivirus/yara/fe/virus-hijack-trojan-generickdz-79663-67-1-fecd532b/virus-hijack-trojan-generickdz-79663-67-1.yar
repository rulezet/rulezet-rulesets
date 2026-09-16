rule Virus_Hijack_Trojan_GenericKDZ_79663_67_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_67_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e8174350abd51dd63060c52a32d4c7b9d9d5c6a3e8f526c7b1768aa93b0e12"

  strings:
    $s1 = "%$KOrE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}