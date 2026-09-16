rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amIMPvn_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "114b8c478a2f524395dcf24db496c3028a8cd3ac2a603c702abac9e359bc2edd"

  strings:
    $s1 = "6policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}