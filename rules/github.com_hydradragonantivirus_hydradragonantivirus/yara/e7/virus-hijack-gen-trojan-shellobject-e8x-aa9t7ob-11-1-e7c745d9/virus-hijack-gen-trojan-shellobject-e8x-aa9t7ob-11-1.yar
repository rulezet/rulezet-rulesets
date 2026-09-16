rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9f6b0e901071c9565c6ca1d9db9043e4277660a11d4683332e12e49b7990dc7"

  strings:
    $s1 = "<Module>{B2E18B94-733A-41C1-A1C5-4761CF06FB85}" fullword ascii
    $s2 = "%soco'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}