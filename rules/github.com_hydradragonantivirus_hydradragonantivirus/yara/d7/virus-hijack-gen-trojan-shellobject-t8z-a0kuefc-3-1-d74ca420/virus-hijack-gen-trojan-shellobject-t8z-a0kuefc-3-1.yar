rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_a0kuefc_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@a0kuefc_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c730bd5137208d03c83adc3ec3db1d0720308dc64e9741aa7120549fc4f0f1da"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" s-Ref:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\"" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}