rule Virus_Hijack_Gen_Trojan_ShellObject_azZ_aKwbXk_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.azZ@aKwbXk_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1eb15205a2574c33b74baf5284a874bcb5946fc784c614112883940b56bf265a"

  strings:
    $s1 = "saNk'M" fullword ascii
    $s2 = "vCallbackListToRpc: begin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}