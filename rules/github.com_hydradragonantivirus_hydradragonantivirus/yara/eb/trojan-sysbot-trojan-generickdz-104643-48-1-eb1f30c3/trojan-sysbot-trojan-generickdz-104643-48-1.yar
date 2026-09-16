rule Trojan_Sysbot_Trojan_GenericKDZ_104643_48_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKDZ.104643_48_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1fc067091c3f90fc585ec9bcca661238a760740a47d3a6012de1e5de101c049"

  strings:
    $s1 = "TRap?<RRRRn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}