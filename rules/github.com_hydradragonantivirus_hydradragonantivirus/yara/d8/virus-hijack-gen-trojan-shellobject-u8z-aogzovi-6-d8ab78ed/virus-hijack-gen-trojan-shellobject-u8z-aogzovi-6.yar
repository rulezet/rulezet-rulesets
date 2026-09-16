rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aOGzovi_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aOGzovi_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c840acb87ccf2b90613e0d7eadf815329bac4527d35bafc52e77e29023f2f89d"

  strings:
    $s1 = "Python 3.9.2 (64-bit)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}