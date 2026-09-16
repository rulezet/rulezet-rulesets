rule Virus_Hijack_Trojan_GenericKDZ_103285_300_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_300_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "718241de0a9bad383780ed35ff25da884ecaa83b6b945b5499b1c8614c4b5f1f"

  strings:
    $s1 = "D=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                 " ascii
    $s2 = "D=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                 " ascii
    $s3 = "tanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}