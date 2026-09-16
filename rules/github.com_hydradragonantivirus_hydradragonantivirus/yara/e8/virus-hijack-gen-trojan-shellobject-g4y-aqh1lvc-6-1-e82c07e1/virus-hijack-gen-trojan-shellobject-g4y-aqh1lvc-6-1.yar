rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_aqH1LVc_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@aqH1LVc_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa1bcd26c1346a1d509b8495765451f637d84687192af49c785379b895920d7f"

  strings:
    $s1 = "SeWn,'L" fullword ascii
    $s2 = " WYDE&" fullword ascii
    $s3 = "J<RAZE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}