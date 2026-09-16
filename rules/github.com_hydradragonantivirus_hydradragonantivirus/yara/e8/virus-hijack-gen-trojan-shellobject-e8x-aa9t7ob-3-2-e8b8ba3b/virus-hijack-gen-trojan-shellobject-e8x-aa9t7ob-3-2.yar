rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "217d101b037020cbcdd9fb7e67b2dae7ed3e8467b0dad1ca1ac0a160dc39fb48"

  strings:
    $s1 = "WKN gaff" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}