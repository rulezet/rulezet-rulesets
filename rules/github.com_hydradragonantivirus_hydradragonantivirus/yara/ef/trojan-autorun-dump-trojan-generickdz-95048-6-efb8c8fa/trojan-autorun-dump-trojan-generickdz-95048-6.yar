rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_6 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc10ca6a3dd3cc334548e78340380e13a5abcafefd302b8d5f4f6eaee7a1f2b2"

  strings:
    $s1 = "613;gj>8>9;CorF@FACKwzNHNIKS" fullword ascii
    $s2 = "8e9d=66;@mAlE>>CHuItMFFKP}Q|UNNSX" fullword ascii
    $s3 = "f`fack" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}