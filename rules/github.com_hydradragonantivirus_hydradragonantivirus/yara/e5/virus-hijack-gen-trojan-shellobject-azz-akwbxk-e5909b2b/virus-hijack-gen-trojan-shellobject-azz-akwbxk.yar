rule Virus_Hijack_Gen_Trojan_ShellObject_azZ_aKwbXk {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.azZ@aKwbXk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5677690ff39f1001473c931e655169c0e189bef100d4c4a153cda0eeca3a2fcd"

  strings:
    $s1 = "vCallbackListToRpc: begin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}