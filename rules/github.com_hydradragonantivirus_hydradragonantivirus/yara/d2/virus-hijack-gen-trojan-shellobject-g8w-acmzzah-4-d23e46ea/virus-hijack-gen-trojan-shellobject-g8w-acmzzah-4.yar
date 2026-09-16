rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aCMzZah_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aCMzZah_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c49162ee72b00fda0620f8b6aa1eda726a83b8ed2f116aa948e7659e3e30eea"

  strings:
    $s1 = "Norders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}