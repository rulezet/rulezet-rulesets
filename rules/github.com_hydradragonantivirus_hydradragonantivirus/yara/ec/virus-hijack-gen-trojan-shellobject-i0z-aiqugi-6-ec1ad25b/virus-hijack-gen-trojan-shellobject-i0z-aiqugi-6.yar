rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a23b3df7006d59a8bbd60811d8771a9e5732bc68e18e9efe43ff26d8fab10254"

  strings:
    $s1 = "v4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}