rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a494884cc8577f670c3883861fbf57b6745bc2302bad5d413162dad925c09191"

  strings:
    $s1 = "Fneed dictionary" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}