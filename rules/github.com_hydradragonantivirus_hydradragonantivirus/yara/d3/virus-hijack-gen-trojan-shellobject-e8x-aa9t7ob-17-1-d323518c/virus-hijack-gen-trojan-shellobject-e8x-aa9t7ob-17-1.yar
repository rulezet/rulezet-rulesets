rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf2c814ade54ce77c12ad089043709d78281e6b0433fbbd8010663e01a976b8"

  strings:
    $s1 = "Select * from AntiVirusProduct" fullword wide
    $s2 = "alive??" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}