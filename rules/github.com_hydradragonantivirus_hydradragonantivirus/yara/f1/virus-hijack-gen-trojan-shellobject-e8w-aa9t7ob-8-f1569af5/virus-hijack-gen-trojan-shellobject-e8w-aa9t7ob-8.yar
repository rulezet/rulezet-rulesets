rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "427f4a00d34c5734f0ad546fd384540fcd257f89ebfa298c58ece7cb349b3d71"

  strings:
    $s1 = "Chundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}