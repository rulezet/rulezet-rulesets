rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aqOJzSd_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c81686948ec070560754be2a52c2fb8d038314e30d7e1952a18d9e5b2cc190a3"

  strings:
    $s1 = "pUcE Software" fullword wide
    $s2 = "Enjoy !" fullword wide
    $s3 = "!'%s' is not a valid integer value\"'%s' is not a valid currency value!'%g' is not a valid date and timeInvalid argument to tim" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}