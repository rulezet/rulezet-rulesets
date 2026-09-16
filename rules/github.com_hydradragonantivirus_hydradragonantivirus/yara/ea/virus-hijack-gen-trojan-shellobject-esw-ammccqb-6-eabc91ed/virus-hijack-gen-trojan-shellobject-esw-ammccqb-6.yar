rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2523b7e16a95c6355c784d9f618dc6c430a884233230d0404430a204c8be52d3"

  strings:
    $s1 = "dwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}