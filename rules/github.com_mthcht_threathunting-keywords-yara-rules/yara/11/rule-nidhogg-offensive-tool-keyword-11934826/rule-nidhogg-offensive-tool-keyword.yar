rule rule_Nidhogg_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Nidhogg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nidhogg"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Nidhogg_offensive_tool_keyword = /\/Nidhogg\.cpp/ nocase ascii wide
                        $string2_Nidhogg_offensive_tool_keyword = /\/Nidhogg\.exe/ nocase ascii wide
                        $string3_Nidhogg_offensive_tool_keyword = /\/Nidhogg\.git/ nocase ascii wide
                        $string4_Nidhogg_offensive_tool_keyword = /\/Nidhogg\.zip/ nocase ascii wide
                        $string5_Nidhogg_offensive_tool_keyword = /\/NidhoggClient\.exe/ nocase ascii wide
                        $string6_Nidhogg_offensive_tool_keyword = "/NidhoggClient/" nocase ascii wide
                        $string7_Nidhogg_offensive_tool_keyword = /\\\\\.\\Nidhogg/ nocase ascii wide
                        $string8_Nidhogg_offensive_tool_keyword = /\\\\\?\?\\\\Nidhogg/ nocase ascii wide
                        $string9_Nidhogg_offensive_tool_keyword = /\\\\Device\\\\Nidhogg/ nocase ascii wide
                        $string10_Nidhogg_offensive_tool_keyword = /\\\\Device\\\\Nidhogg/ nocase ascii wide
                        $string11_Nidhogg_offensive_tool_keyword = /\\\\Driver\\\\Nidhogg/ nocase ascii wide
                        $string12_Nidhogg_offensive_tool_keyword = /\\Nidhogg\.cpp/ nocase ascii wide
                        $string13_Nidhogg_offensive_tool_keyword = /\\Nidhogg\.exe/ nocase ascii wide
                        $string14_Nidhogg_offensive_tool_keyword = /\\Nidhogg\.sln/ nocase ascii wide
                        $string15_Nidhogg_offensive_tool_keyword = /\\Nidhogg\.sys/ nocase ascii wide
                        $string16_Nidhogg_offensive_tool_keyword = /\\NidhoggClient\.exe/ nocase ascii wide
                        $string17_Nidhogg_offensive_tool_keyword = /\\NidhoggClient\\/ nocase ascii wide
                        $string18_Nidhogg_offensive_tool_keyword = "13C57810-FF18-4258-ABC9-935040A54F0B" nocase ascii wide
                        $string19_Nidhogg_offensive_tool_keyword = /CatalogFile\=Nidhogg\.cat/ nocase ascii wide
                        $string20_Nidhogg_offensive_tool_keyword = "Idov31/Nidhogg" nocase ascii wide
                        $string21_Nidhogg_offensive_tool_keyword = /include\s.{0,100}Nidhogg\.hpp/ nocase ascii wide
                        $string22_Nidhogg_offensive_tool_keyword = "Nidhogg rootkit" nocase ascii wide
                        $string23_Nidhogg_offensive_tool_keyword = /Nidhogg.{0,100}AntiAnalysis\.hpp/ nocase ascii wide
                        $string24_Nidhogg_offensive_tool_keyword = "Nidhogg::AntiAnalysis::NidhoggDisableCallback" nocase ascii wide
                        $string25_Nidhogg_offensive_tool_keyword = "Nidhogg::AntiAnalysis::NidhoggEnableDisableEtwTi" nocase ascii wide
                        $string26_Nidhogg_offensive_tool_keyword = "Nidhogg::AntiAnalysis::NidhoggListObCallbacks" nocase ascii wide
                        $string27_Nidhogg_offensive_tool_keyword = "Nidhogg::AntiAnalysis::NidhoggListPsRoutines" nocase ascii wide
                        $string28_Nidhogg_offensive_tool_keyword = "Nidhogg::AntiAnalysis::NidhoggListRegistryCallbacks" nocase ascii wide
                        $string29_Nidhogg_offensive_tool_keyword = "Nidhogg::AntiAnalysis::NidhoggRestoreCallback" nocase ascii wide
                        $string30_Nidhogg_offensive_tool_keyword = "Nidhogg::FileUtils::NidhoggFileClearAllProtection" nocase ascii wide
                        $string31_Nidhogg_offensive_tool_keyword = "Nidhogg::FileUtils::NidhoggFileProtect" nocase ascii wide
                        $string32_Nidhogg_offensive_tool_keyword = "Nidhogg::FileUtils::NidhoggFileUnprotect" nocase ascii wide
                        $string33_Nidhogg_offensive_tool_keyword = "Nidhogg::FileUtils::NidhoggQueryFiles" nocase ascii wide
                        $string34_Nidhogg_offensive_tool_keyword = "Nidhogg::ModuleUtils::NidhoggAmsiBypass" nocase ascii wide
                        $string35_Nidhogg_offensive_tool_keyword = "Nidhogg::ModuleUtils::NidhoggETWBypass" nocase ascii wide
                        $string36_Nidhogg_offensive_tool_keyword = "Nidhogg::ModuleUtils::NidhoggInjectDll" nocase ascii wide
                        $string37_Nidhogg_offensive_tool_keyword = "Nidhogg::ModuleUtils::NidhoggInjectShellcode" nocase ascii wide
                        $string38_Nidhogg_offensive_tool_keyword = "Nidhogg::ModuleUtils::NidhoggPatchModule" nocase ascii wide
                        $string39_Nidhogg_offensive_tool_keyword = "Nidhogg::ModuleUtils::NidhoggReadData" nocase ascii wide
                        $string40_Nidhogg_offensive_tool_keyword = "Nidhogg::ModuleUtils::NidhoggWriteData" nocase ascii wide
                        $string41_Nidhogg_offensive_tool_keyword = "Nidhogg::ProcessUtils::NidhoggProcessClearAllProtection" nocase ascii wide
                        $string42_Nidhogg_offensive_tool_keyword = "Nidhogg::ProcessUtils::NidhoggProcessElevate" nocase ascii wide
                        $string43_Nidhogg_offensive_tool_keyword = "Nidhogg::ProcessUtils::NidhoggProcessHide" nocase ascii wide
                        $string44_Nidhogg_offensive_tool_keyword = "Nidhogg::ProcessUtils::NidhoggProcessProtect" nocase ascii wide
                        $string45_Nidhogg_offensive_tool_keyword = "Nidhogg::ProcessUtils::NidhoggProcessSetProtection" nocase ascii wide
                        $string46_Nidhogg_offensive_tool_keyword = "Nidhogg::ProcessUtils::NidhoggProcessUnhide" nocase ascii wide
                        $string47_Nidhogg_offensive_tool_keyword = "Nidhogg::ProcessUtils::NidhoggProcessUnprotect" nocase ascii wide
                        $string48_Nidhogg_offensive_tool_keyword = "Nidhogg::ProcessUtils::NidhoggQueryProcesses" nocase ascii wide
                        $string49_Nidhogg_offensive_tool_keyword = "Nidhogg::ProcessUtils::NidhoggQueryThreads" nocase ascii wide
                        $string50_Nidhogg_offensive_tool_keyword = "Nidhogg::ProcessUtils::NidhoggThreadHide" nocase ascii wide
                        $string51_Nidhogg_offensive_tool_keyword = "Nidhogg::ProcessUtils::NidhoggThreadProtect" nocase ascii wide
                        $string52_Nidhogg_offensive_tool_keyword = "Nidhogg::RegistryUtils::NidhoggRegistryClearAll" nocase ascii wide
                        $string53_Nidhogg_offensive_tool_keyword = "Nidhogg::RegistryUtils::NidhoggRegistryHideKey" nocase ascii wide
                        $string54_Nidhogg_offensive_tool_keyword = "Nidhogg::RegistryUtils::NidhoggRegistryHideValue" nocase ascii wide
                        $string55_Nidhogg_offensive_tool_keyword = "Nidhogg::RegistryUtils::NidhoggRegistryProtectKey" nocase ascii wide
                        $string56_Nidhogg_offensive_tool_keyword = "Nidhogg::RegistryUtils::NidhoggRegistryProtectValue" nocase ascii wide
                        $string57_Nidhogg_offensive_tool_keyword = "Nidhogg::RegistryUtils::NidhoggRegistryQueryHiddenKeys" nocase ascii wide
                        $string58_Nidhogg_offensive_tool_keyword = "Nidhogg::RegistryUtils::NidhoggRegistryQueryHiddenValues" nocase ascii wide
                        $string59_Nidhogg_offensive_tool_keyword = "Nidhogg::RegistryUtils::NidhoggRegistryQueryProtectedKeys" nocase ascii wide
                        $string60_Nidhogg_offensive_tool_keyword = "Nidhogg::RegistryUtils::NidhoggRegistryQueryProtectedValues" nocase ascii wide
                        $string61_Nidhogg_offensive_tool_keyword = "Nidhogg::RegistryUtils::NidhoggRegistryUnhideKey" nocase ascii wide
                        $string62_Nidhogg_offensive_tool_keyword = "Nidhogg::RegistryUtils::NidhoggRegistryUnhideValue" nocase ascii wide
                        $string63_Nidhogg_offensive_tool_keyword = "Nidhogg::RegistryUtils::NidhoggRegistryUnprotectValue" nocase ascii wide
                        $string64_Nidhogg_offensive_tool_keyword = /Nidhogg\-0\.1\.zip/ nocase ascii wide
                        $string65_Nidhogg_offensive_tool_keyword = /Nidhogg\-0\.2\.zip/ nocase ascii wide
                        $string66_Nidhogg_offensive_tool_keyword = /Nidhogg\-0\.3\.zip/ nocase ascii wide
                        $string67_Nidhogg_offensive_tool_keyword = /Nidhogg\-0\.4\.zip/ nocase ascii wide
                        $string68_Nidhogg_offensive_tool_keyword = /Nidhogg\-0\.5\.zip/ nocase ascii wide
                        $string69_Nidhogg_offensive_tool_keyword = /NidhoggClient\.exe\s/ nocase ascii wide
                        $string70_Nidhogg_offensive_tool_keyword = /NidhoggExample\.cpp/ nocase ascii wide
                        $string71_Nidhogg_offensive_tool_keyword = "Nidhogg-master" nocase ascii wide
                        $string72_Nidhogg_offensive_tool_keyword = "sc start nidhogg" nocase ascii wide
                        $string73_Nidhogg_offensive_tool_keyword = /tNidhoggClient\.exe/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}