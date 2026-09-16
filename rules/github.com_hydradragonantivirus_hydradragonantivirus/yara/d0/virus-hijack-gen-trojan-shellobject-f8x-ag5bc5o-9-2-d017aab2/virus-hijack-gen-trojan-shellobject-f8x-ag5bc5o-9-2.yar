rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d556cf7c7d33bb32aaad1ff82c263aa19b31c3b8591cdc2475c2f4c4f5d08b0"

  strings:
    $x1  = "\"20210702161056.990\",\"776\",\"HelpMe.exe\",\"148\",\"registry\",\"RegOpenKeyExW\",\"FAILURE\",\"\",\"hKey->HKEY_LOCAL_MACHINE" ascii
    $x2  = "\"20210702161102.037\",\"776\",\"HelpMe.exe\",\"148\",\"registry\",\"RegSetValueExW\",\"SUCCESS\",\"\",\"hKey->0x000001c8\",\"lp" ascii
    $x3  = "\"20210729101507.804\",\"1344\",\"cb6db5d6d8a8d0935cdc03f22d50f2ca6e6ce54623a287298fa4bb25f7e0cac4\",\"1596\",\"process\",\"Crea" ascii
    $x4  = "\"20210826080531.535\",\"420\",\"902e4f71eff49837fd6e23758b2c5f89d8d0980dd8f2112bad2f342230828252\",\"1204\",\"process\",\"Creat" ascii
    $x5  = "\"20210702161102.017\",\"776\",\"HelpMe.exe\",\"148\",\"registry\",\"RegSetValueExW\",\"SUCCESS\",\"\",\"hKey->0x000001c8\",\"lp" ascii
    $x6  = "\"20210702161102.188\",\"776\",\"HelpMe.exe\",\"148\",\"registry\",\"RegSetValueExW\",\"SUCCESS\",\"\",\"hKey->0x000001dc\",\"lp" ascii
    $x7  = "\"20210729103007.831\",\"208\",\"898b8cf8f07ebba00525c08cde32252cbec11a28880fdd6636fd6408a96ec6d4\",\"1780\",\"process\",\"Creat" ascii
    $x8  = "\"20210702161102.158\",\"776\",\"HelpMe.exe\",\"148\",\"registry\",\"RegSetValueExW\",\"SUCCESS\",\"\",\"hKey->0x000001e4\",\"lp" ascii
    $x9  = "\"20210702161102.087\",\"776\",\"HelpMe.exe\",\"148\",\"registry\",\"RegOpenKeyExW\",\"SUCCESS\",\"0x000001c8\",\"hKey->0x000001" ascii
    $x10 = "\"20210702161102.037\",\"776\",\"HelpMe.exe\",\"148\",\"registry\",\"RegCreateKeyExW\",\"SUCCESS\",\"0x000001cc\",\"hKey->HKEY_C" ascii
    $x11 = "\"20210702161101.977\",\"776\",\"HelpMe.exe\",\"148\",\"registry\",\"RegCreateKeyExW\",\"SUCCESS\",\"0x00000144\",\"hKey->HKEY_C" ascii
    $x12 = "\"20210702161102.158\",\"776\",\"HelpMe.exe\",\"148\",\"registry\",\"RegCreateKeyExW\",\"SUCCESS\",\"0x000001dc\",\"hKey->HKEY_C" ascii
    $x13 = "\"20210702161102.188\",\"776\",\"HelpMe.exe\",\"148\",\"registry\",\"RegCreateKeyExW\",\"SUCCESS\",\"0x000001e4\",\"hKey->HKEY_C" ascii
    $x14 = "\"20210702161102.017\",\"776\",\"HelpMe.exe\",\"148\",\"registry\",\"RegCreateKeyExW\",\"SUCCESS\",\"0x000001cc\",\"hKey->HKEY_C" ascii
    $x15 = "ware\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\HelpMe.exe\\RpcThreadPoolThrottle\"" fullword ascii
    $s16 = "\"20210826080536.482\",\"420\",\"902e4f71eff49837fd6e23758b2c5f89d8d0980dd8f2112bad2f342230828252\",\"1204\",\"registry\",\"RegO" ascii
    $s17 = "\"20211019151519.391\",\"1352\",\"fea4ae009c80a6b2040015f54dbd7eb016b64e412105e98c5e73deeba7321423\",\"1548\",\"registry\",\"Reg" ascii
    $s18 = "\"20210729101512.781\",\"1344\",\"cb6db5d6d8a8d0935cdc03f22d50f2ca6e6ce54623a287298fa4bb25f7e0cac4\",\"1596\",\"registry\",\"Reg" ascii
    $s19 = "\"20210729103012.829\",\"208\",\"898b8cf8f07ebba00525c08cde32252cbec11a28880fdd6636fd6408a96ec6d4\",\"1780\",\"registry\",\"RegO" ascii
    $s20 = "\"20210826080536.753\",\"420\",\"902e4f71eff49837fd6e23758b2c5f89d8d0980dd8f2112bad2f342230828252\",\"1204\",\"registry\",\"RegS" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}