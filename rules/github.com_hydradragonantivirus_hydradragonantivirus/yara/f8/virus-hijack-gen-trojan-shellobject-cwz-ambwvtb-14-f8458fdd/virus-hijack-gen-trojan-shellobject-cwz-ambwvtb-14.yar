rule Virus_Hijack_Gen_Trojan_ShellObject_CwZ_amBwvTb_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.CwZ@amBwvTb_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "807e9227a37f92dd68a8450e218821cf5138dae4b1901ef25b5702796626498f"

  strings:
    $s1 = "(NASi'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}