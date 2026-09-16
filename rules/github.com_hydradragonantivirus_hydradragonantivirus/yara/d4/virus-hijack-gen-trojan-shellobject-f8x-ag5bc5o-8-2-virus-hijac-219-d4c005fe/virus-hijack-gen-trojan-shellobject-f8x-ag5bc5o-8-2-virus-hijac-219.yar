rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_8_2_Virus_Hijac_219 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_14_2.vir, VirusShareTrojanSiggen817711.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a0f644cb37624ab9f60b7e6706582255a016628c8c78c94d829ecc3ac9429f6"
    hash2       = "a1f73c852f46af89ba4d6ffa45263ad6de9327da6f3ffef7218213441bdfab73"
    hash3       = "50352927df7d25fd238015087b304fbb5a4180ac8743ad9462c9e726535e996a"
    hash4       = "64d7be253b0683466635cb9ccab39bee55c812e9330814b6ce3a44039ddb5ef5"
    hash5       = "c47d2baf377420863029283acb7f69d110fe7c2387caa25e3365126e3e4a7495"
    hash6       = "bd6de74eabbdb72321816001868b945a08876fea3495d6f5f7af2598923b5ab1"

  strings:
    $s1  = "\"20201105030907.787\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s2  = "\",\"SUCCESS\",\"\",\"hKey->0x0000020c\",\"lpValueName->Common AppData\",\"dwType->1\",\"lpData->C:\\Documents and Settings\\All" ascii
    $s3  = "\",\"SUCCESS\",\"\",\"hKey->0x0000020c\",\"lpValueName->Common Start Menu\",\"dwType->1\",\"lpData->C:\\Documents and Settings" ascii
    $s4  = "\"20201105030907.777\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s5  = "\"20201105030907.787\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s6  = "\"20201105030907.697\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s7  = "\"20201105030907.777\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s8  = "\"20201105030907.787\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s9  = "\"20201105030907.767\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s10 = "W\",\"SUCCESS\",\"0x000001f8\",\"hKey->HKEY_CURRENT_USER\",\"lpSubKey->Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\U" ascii
    $s11 = "\",\"SUCCESS\",\"\",\"hKey->0x000001f8\",\"lpValueName->Start Menu\",\"dwType->1\",\"lpData->C:\\Documents and Settings\\janette" ascii
    $s12 = ",\"SUCCESS\",\"0x000001d8\",\"hKey->0x000001d0\",\"lpSubKey->Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell " ascii
    $s13 = "\"20201105030907.767\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s14 = "W\",\"SUCCESS\",\"0x0000020c\",\"hKey->HKEY_LOCAL_MACHINE\",\"lpSubKey->Software\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii
    $s15 = "xW\",\"SUCCESS\",\"\",\"hKey->0x0000020c\",\"lpValueName->Common AppData\"" fullword ascii
    $s16 = "\"20201105030907.787\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s17 = "xW\",\"SUCCESS\",\"\",\"hKey->0x0000020c\",\"lpValueName->Common Start Menu\"" fullword ascii
    $s18 = ",\"SUCCESS\",\"0x00000144\",\"lpFileName->C:\\105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"dwDesiredAcce" ascii
    $s19 = "\"20201105030907.777\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s20 = "xW\",\"SUCCESS\",\"\",\"hKey->0x000001f8\",\"lpValueName->Start Menu\"" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}