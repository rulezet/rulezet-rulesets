rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "309cbde15d9a922320e2416bfcab91843403559b10bb3bd0a25b85c3487f8428"

  strings:
    $s1 = "Welcome to use storm ddos" fullword ascii
    $s2 = "Storm ddos Server" fullword ascii
    $s3 = "Program Files\\Internet Explorer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}