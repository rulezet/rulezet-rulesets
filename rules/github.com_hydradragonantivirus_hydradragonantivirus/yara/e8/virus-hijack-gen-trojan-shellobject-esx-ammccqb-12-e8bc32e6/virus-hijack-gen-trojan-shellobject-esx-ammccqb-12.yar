rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c9d26da00762f67f782a890b3bad6cb4d146cbcd8b1e9a3f9f2324b390403a7"

  strings:
    $s1 = "Welcome to use storm ddos" fullword ascii
    $s2 = "Storm ddos Server" fullword ascii
    $s3 = "Program Files\\Internet Explorer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}