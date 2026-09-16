rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_73 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_73.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a046c262110afcd8cd61699e2ea3d1f5b4560e30443225395136804add67ecc"

  strings:
    $s1 = "%4. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "KuLa?r-b2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}