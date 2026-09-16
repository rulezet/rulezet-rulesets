rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2ee0f956f7a976ddd516082d22c5fc6bcab1332fb536d75c0f52f006e43b4cf"

  strings:
    $s1 = "Meliorate" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}