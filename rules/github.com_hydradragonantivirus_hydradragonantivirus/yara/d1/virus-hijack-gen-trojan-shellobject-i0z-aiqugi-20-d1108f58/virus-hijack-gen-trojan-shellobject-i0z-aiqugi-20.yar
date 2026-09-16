rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "823f2d47f3f64843c1413bdeb06dbd3ed5e9cda6820bcaafe6ef4d2bdf67dce9"

  strings:
    $s1 = "_@4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}