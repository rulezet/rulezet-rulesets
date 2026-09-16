rule Virus_Hijack_Gen_Trojan_ShellObject_v8Z_aqDKVYh_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v8Z@aqDKVYh_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5424f305e7ca6a122e71a9964071eb667773793acb554df4b06b64ce0dc1f019"

  strings:
    $s1 = "]lorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}