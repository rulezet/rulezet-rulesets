rule Trojan_Danger_Trojan_GenericKD_72853156_426_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_426_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc898af36dda6b750a9928ff051b3cfe5bffd6893d2d6b4fd70486faa4745e7e"

  strings:
    $s1 = "aIde]~{" fullword ascii
    $s2 = "belY{-" fullword ascii
    $s3 = "iNlY;1" fullword ascii
    $s4 = "JT&CuRt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}