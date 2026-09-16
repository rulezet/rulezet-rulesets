rule Virus_Hijack_Gen_Trojan_ShellObject_LzZ_aWELKOd_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.LzZ@aWELKOd_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a22db4cbb1e5013b8da31dd5be4d0d133e8519d28ec1ada9932cd83270e6bd37"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}