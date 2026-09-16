rule Virus_Hijack_Trojan_GenericKDZ_98113_348 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_348.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb398bf248a80f280270eb4083b68431cb9029e898382fb62041f00b61e274e8"

  strings:
    $s1 = "j=by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}