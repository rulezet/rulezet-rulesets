rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_ayWIjmh_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@ayWIjmh_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c9f8e30e438c02fbcab2e669e43456d79347c8618305fe4935786407dc08c83"

  strings:
    $s1 = "}your order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}