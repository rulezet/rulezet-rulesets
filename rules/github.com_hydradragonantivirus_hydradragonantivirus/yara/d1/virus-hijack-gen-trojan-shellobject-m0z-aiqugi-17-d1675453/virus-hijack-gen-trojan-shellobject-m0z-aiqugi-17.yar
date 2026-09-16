rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee57ceddb860a9f25ef7f89372ca371fa5c9e99bb6d0a542f0a2c21612627e80"

  strings:
    $s1 = "O4. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "tImE @gUoTjB.!kP GvWuE$Yn" fullword ascii
    $s3 = "TImE QvYgSe[ BeXnNp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}