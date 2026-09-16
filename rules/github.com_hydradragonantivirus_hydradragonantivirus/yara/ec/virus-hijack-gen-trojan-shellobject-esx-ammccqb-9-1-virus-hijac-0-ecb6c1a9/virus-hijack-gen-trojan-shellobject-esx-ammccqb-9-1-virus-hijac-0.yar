import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_9_1_Virus_Hijac_0 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_14.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf3de637207c5993f61bca8107409296377a79fd64b723dc0ce110d9f7d503a7"
    hash2       = "cf2579127f14476437bf1be9644f0f3ae0f11ba34b9cc2e6f9a0c7c3b8ad4a2c"
    hash3       = "b48a71e1bc743002f572bfac597587d96b7cdc6d72d89dbe42fe0c28b3ece36a"
    hash4       = "ea056eb8dd0e644ab352332b94da04e683779717d0c550d169e5feb987c37508"
    hash5       = "375745aabed8a27ff352a744da9602f2502cf60472888d659161b6a67467988f"
    hash6       = "9eb2bf0db3cc911cb7fba2b2c1ada2995742f8fcbc19636a5e544932f7d8d63e"
    hash7       = "31f3b63e351fcfe73bcf0a1876f616c523342d0894c91f8dcb527b2f84de3ba0"

  strings:
    $s1  = "import_module(code, initfunc, dllname[, finder]) -> module" fullword ascii
    $s2  = "The logfile '%s' could not be opened:" fullword ascii
    $s3  = "undefined symbol %s -> exit(-1)" fullword ascii
    $s4  = "MemoryLoadLibrary failed loading %s" fullword ascii
    $s5  = "Could not load script resource:" fullword ascii
    $s6  = "Bug: Invalid script resource" fullword ascii
    $s7  = "Could not lock script resource:" fullword ascii
    $s8  = "Could not load python dll" fullword ascii
    $s9  = "<install zipextimporter>R$" fullword ascii
    $s10 = "Thread(" fullword ascii
    $s11 = "undef symbol" fullword ascii
    $s12 = "no mem for late sys.path" fullword ascii
    $s13 = "TrueR?" fullword ascii
    $s14 = "FalseR@" fullword ascii
    $s15 = "install(" fullword ascii
    $s16 = "<module>," fullword ascii
    $s17 = "Return the Py_Verbose flag" fullword ascii
    $s18 = "closeR<" fullword ascii
    $s19 = "Not enough space for new sys.path" fullword ascii
    $s20 = "Importer which can load extension modules from memory" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "7af2fe87a3ab930007d141d21c36ceda" and (8 of them)
    ) or (all of them)
}