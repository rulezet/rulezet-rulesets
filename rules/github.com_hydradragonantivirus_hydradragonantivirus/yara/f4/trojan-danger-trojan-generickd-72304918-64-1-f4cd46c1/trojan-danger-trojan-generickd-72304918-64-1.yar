rule Trojan_Danger_Trojan_GenericKD_72304918_64_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_64_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51ef19d696e08bbf8e1cfcf2465944f881da09c99b730408e3974d58acf4a12a"

  strings:
    $s1 = "deLL{i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}