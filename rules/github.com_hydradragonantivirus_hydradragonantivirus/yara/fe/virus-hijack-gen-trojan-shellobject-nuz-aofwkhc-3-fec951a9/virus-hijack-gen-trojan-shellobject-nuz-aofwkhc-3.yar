rule Virus_Hijack_Gen_Trojan_ShellObject_nuZ_aOFwKHc_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.nuZ@aOFwKHc_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad9457450b84d74c0d34e594399df54a904c381b0f4ce22fac132f5b059f8f36"

  strings:
    $s1 = ";PeNSy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}