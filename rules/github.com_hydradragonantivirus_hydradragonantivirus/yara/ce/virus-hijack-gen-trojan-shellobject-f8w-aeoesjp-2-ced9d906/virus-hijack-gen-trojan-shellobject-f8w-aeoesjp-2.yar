rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aeOesjp_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aeOesjp_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeff8376a596e503161096542750e716befef5ec21ccbcb4215bca5664983258"

  strings:
    $s1 = "FReturns/sets the string displayed when a cursor hovers over an object.XConstants for the OLEDragMode property (but not the Drag" wide
    $s2 = ">Source control dragged from one position in target to another." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}