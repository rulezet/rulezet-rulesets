rule Trojan_Danger_Trojan_GenericKD_67166905_183_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_183_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31958a76bba4dd920322ae42919e7f05531870852265da6d8aac7ad2b5592917"

  strings:
    $s1 = "bInD*^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}