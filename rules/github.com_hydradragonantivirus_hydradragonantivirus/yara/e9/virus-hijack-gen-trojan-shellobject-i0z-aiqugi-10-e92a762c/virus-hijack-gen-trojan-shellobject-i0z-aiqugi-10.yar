rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5af776df520d9c71040d2affa36e58e5f1f1f5bbf911f62ade35a92839bc7bdf"

  strings:
    $s1 = " 4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}