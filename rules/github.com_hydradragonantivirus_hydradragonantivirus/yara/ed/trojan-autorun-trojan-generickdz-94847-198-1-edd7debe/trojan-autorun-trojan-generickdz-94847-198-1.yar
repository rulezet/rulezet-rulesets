rule Trojan_Autorun_Trojan_GenericKDZ_94847_198_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_198_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9ac2993a4dc5c18747b2fdd306e9225013bcc161dc238e09be37df548d95217"

  strings:
    $s1 = "Multiple order entry line items may be entered as part of an individual customer order or quote and may `" fullword ascii
    $s2 = "4that party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}