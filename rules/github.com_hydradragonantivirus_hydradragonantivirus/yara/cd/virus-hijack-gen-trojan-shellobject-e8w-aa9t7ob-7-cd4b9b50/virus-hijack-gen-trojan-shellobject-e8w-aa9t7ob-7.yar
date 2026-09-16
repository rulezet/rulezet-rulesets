rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "699d97b095232e722cec133474d7f472f8d923f352e9cc64bc572deddc6b0ba7"

  strings:
    $s1 = ",hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}