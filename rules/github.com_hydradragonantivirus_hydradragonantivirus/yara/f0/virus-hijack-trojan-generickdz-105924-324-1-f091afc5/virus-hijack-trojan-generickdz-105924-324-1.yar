rule Virus_Hijack_Trojan_GenericKDZ_105924_324_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_324_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "366b0a778c07ab57948780b70c090d5bbf83d425cc04d72b803f79be2fdd214a"

  strings:
    $s1 = "eheu#dg" fullword ascii
    $s2 = "?vARE#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}