rule Virus_Hijack_Gen_Trojan_ShellObject_fCY_aijlKSl_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "255a703e75be25eea8c40a3a7660e0fc3934e9bcb35192d10437f9da0739ee3a"

  strings:
    $s1 = "Determining Windows version" fullword wide
    $s2 = "@CoRegisterClassObject failed with HRESULT = 0x%08x." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}