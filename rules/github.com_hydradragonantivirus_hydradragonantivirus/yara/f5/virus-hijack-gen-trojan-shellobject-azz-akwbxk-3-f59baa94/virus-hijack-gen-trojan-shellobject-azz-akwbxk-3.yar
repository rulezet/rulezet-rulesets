rule Virus_Hijack_Gen_Trojan_ShellObject_azZ_aKwbXk_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.azZ@aKwbXk_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bf86ac62bf83fba72870ec6ef9eadceb8b27d2f6ac5f3998ee31feb4972f48e"

  strings:
    $s1 = "vCallbackListToRpc: begin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}