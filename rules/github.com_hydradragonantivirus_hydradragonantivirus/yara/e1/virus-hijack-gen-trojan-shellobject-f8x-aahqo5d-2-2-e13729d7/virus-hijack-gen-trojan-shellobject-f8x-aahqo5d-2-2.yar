rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aaHqO5d_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aaHqO5d_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49919a9868e8ca863bf4cb63542b33f95ada3ef0e7e8c3827bedba9a70169254"

  strings:
    $s1 = " <rdf:Description about='uuid:6d39c6d2-21ce-11d7-9cf3-c01b0f5ad522'" fullword ascii
    $s2 = "  <xapMM:DocumentID>adobe:docid:photoshop:6d39c6c9-21ce-11d7-9cf3-c01b0f5ad522</xapMM:DocumentID>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}