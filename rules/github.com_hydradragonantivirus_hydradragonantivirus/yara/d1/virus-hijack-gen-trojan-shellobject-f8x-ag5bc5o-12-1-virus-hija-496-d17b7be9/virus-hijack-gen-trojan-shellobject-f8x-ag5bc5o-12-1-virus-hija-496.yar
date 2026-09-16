rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_12_1_Virus_Hija_496 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_12.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97121aeedf128abc5ad8715f79d3696d32348a8c453f7e1415a75f72b756049d"
    hash2       = "f91e29b13b06cd530269c794e52d77cc838fa87a0cd6c6d81cb492f8f246468b"
    hash3       = "5d9804ff2d27070141d1d4026f463726ee4df82e182a45804922613d9e80c7d3"
    hash4       = "19cbcc29628d4c642c52ee515e5c0cadbee9dbc08e29cd2abf9ce25ab121a57b"
    hash5       = "c2816a5380456292f9574b067d7b3197da5210eadcc6b2977fcf8b8eac5fd135"
    hash6       = "293cc6207e0313f3e6e3e9fce113d6f7a2f721942b9fab96da2318d55bc5d66e"

  strings:
    $s1 = "%s %s processor(s)" fullword ascii
    $s2 = "FILE DOWNLOADED" fullword ascii
    $s3 = "SYSTEM GOING FOR REBOOT NOW" fullword ascii
    $s4 = "FILE UPLOADED" fullword ascii
    $s5 = "MESSAGEBOX DISPLAYED" fullword ascii
    $s6 = "DIR NOT FOUND" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}