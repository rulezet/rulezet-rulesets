rule Virus_Hijack_Gen_Trojan_ShellObject_azZ_aKwbXk_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.azZ@aKwbXk_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18354ae4893c417d3d87a5653e6202deece4fee6450f8214b23c4b855dd67d5c"

  strings:
    $s1 = "vCallbackListToRpc: begin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}