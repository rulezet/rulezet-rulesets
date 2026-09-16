rule VirusShareTrojanSiggen1527079_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1527079_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c1e8c62124a950f5f5de49184b28ffeb8f00c3e11538a389bd3484f5e9d29cc"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "tOtE>sYq" fullword ascii
    $s3 = "GRiCE*" fullword ascii
    $s4 = "NOIl<D" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}