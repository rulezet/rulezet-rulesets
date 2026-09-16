rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef5a35dde909cd26d7d9430e1f3ca4d218ad542d05366f100a1d955381b4b153"

  strings:
    $s1 = "Set Program Access and Defaults" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}