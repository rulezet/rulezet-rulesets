rule _Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aerna7n_2_1_VirusShareT_498 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aerna7n_2_1.vir, VirusShareTrojanDownLoader4345326.vir, VirusShareTrojanDownLoader4346565.vir, VirusShareTrojanDownLoader4347106.vir, VirusShareTrojanPWSStealer31365_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "515f91b73a4da057065c29ebbecbae70321dc098e67f2f0e6528f1be3a69f5cd"
    hash2       = "e9a905d9e522c0feed6b811e113bb2fe6e642118902e5a9e2528282bb6fbe179"
    hash3       = "e7d5694ad906b707cd6aef9df07e2651fe947441fc4cfa8a55a6651da6e59b20"
    hash4       = "a1c59b89c79d51496bca3bb67723db963900699f5db3b9e4f09fae181c9a9120"
    hash5       = "76b7e0265f5fd3d3fead08df85a41d4fac0ab5bd881f9c44dca6987e69c9b63c"

  strings:
    $s1 = "No Message processing node setJSoap header %s with attribute 'mustUnderstand' set to true was not handled" fullword wide
    $s2 = "Type mismatch in parameter %s3No method named '%s' is supported by interface '%s'#Interface not registered, UUID = %s Interface " wide
    $s3 = "Method has no RTTI" fullword wide
    $s4 = "Invalid hour: %d" fullword wide
    $s5 = "Invalid second: %d" fullword wide
    $s6 = "Invalid day: %d" fullword wide
    $s7 = "Invalid month: %d" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}