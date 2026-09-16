rule Trojan_Autorun_Trojan_GenericKDZ_94847_272_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_272_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "904452d20bf17ce5f3ec7a663cbe9a13cc24fb240598046db75d471e73a139fe"

  strings:
    $s1 = "dowhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}