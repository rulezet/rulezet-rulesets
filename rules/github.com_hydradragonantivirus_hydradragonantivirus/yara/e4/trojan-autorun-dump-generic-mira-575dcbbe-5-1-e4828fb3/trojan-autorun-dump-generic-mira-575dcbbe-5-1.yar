rule Trojan_Autorun_Dump_Generic_Mira_575DCBBE_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Mira.575DCBBE_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3db9eb01ecade194cb92dece8d47078694a6af92d8f9bd20e433a19fee9689fd"

  strings:
    $s1 = "Vcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}