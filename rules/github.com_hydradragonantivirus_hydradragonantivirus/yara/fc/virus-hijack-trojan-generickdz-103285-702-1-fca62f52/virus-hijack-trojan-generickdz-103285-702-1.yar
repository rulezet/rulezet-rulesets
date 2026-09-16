rule Virus_Hijack_Trojan_GenericKDZ_103285_702_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_702_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1ee52267560f5134921e35ac79e59ba548e95b73b9623fe83ef0531192369b3"

  strings:
    $s1 = ".com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmpMM" ascii
    $s2 = "ww.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=\"http://ns.adob" fullword ascii
    $s3 = " xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"htt" ascii
    $s4 = "p/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateDate=\"2018-12-02T15:50:06+08:00\" xm" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}