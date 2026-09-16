rule Nidhogg
{
    meta:
        description = "Detection patterns for the tool 'Nidhogg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nidhogg"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Nidhogg\.cpp/ nocase ascii wide
                        $string2 = /\/Nidhogg\.exe/ nocase ascii wide
                        $string3 = /\/Nidhogg\.git/ nocase ascii wide
                        $string4 = /\/Nidhogg\.zip/ nocase ascii wide
                        $string5 = /\/NidhoggClient\.exe/ nocase ascii wide
                        $string6 = "/NidhoggClient/" nocase ascii wide
                        $string7 = /\\\\\.\\Nidhogg/ nocase ascii wide
                        $string8 = /\\\\\?\?\\\\Nidhogg/ nocase ascii wide
                        $string9 = /\\\\Device\\\\Nidhogg/ nocase ascii wide
                        $string10 = /\\\\Device\\\\Nidhogg/ nocase ascii wide
                        $string11 = /\\\\Driver\\\\Nidhogg/ nocase ascii wide
                        $string12 = /\\Nidhogg\.cpp/ nocase ascii wide
                        $string13 = /\\Nidhogg\.exe/ nocase ascii wide
                        $string14 = /\\Nidhogg\.sln/ nocase ascii wide
                        $string15 = /\\Nidhogg\.sys/ nocase ascii wide
                        $string16 = /\\NidhoggClient\.exe/ nocase ascii wide
                        $string17 = /\\NidhoggClient\\/ nocase ascii wide
                        $string18 = "13C57810-FF18-4258-ABC9-935040A54F0B" nocase ascii wide
                        $string19 = /CatalogFile\=Nidhogg\.cat/ nocase ascii wide
                        $string20 = "Idov31/Nidhogg" nocase ascii wide
                        $string21 = /include\s.{0,1000}Nidhogg\.hpp/ nocase ascii wide
                        $string22 = "Nidhogg rootkit" nocase ascii wide
                        $string23 = /Nidhogg.{0,1000}AntiAnalysis\.hpp/ nocase ascii wide
                        $string24 = "Nidhogg::AntiAnalysis::NidhoggDisableCallback" nocase ascii wide
                        $string25 = "Nidhogg::AntiAnalysis::NidhoggEnableDisableEtwTi" nocase ascii wide
                        $string26 = "Nidhogg::AntiAnalysis::NidhoggListObCallbacks" nocase ascii wide
                        $string27 = "Nidhogg::AntiAnalysis::NidhoggListPsRoutines" nocase ascii wide
                        $string28 = "Nidhogg::AntiAnalysis::NidhoggListRegistryCallbacks" nocase ascii wide
                        $string29 = "Nidhogg::AntiAnalysis::NidhoggRestoreCallback" nocase ascii wide
                        $string30 = "Nidhogg::FileUtils::NidhoggFileClearAllProtection" nocase ascii wide
                        $string31 = "Nidhogg::FileUtils::NidhoggFileProtect" nocase ascii wide
                        $string32 = "Nidhogg::FileUtils::NidhoggFileUnprotect" nocase ascii wide
                        $string33 = "Nidhogg::FileUtils::NidhoggQueryFiles" nocase ascii wide
                        $string34 = "Nidhogg::ModuleUtils::NidhoggAmsiBypass" nocase ascii wide
                        $string35 = "Nidhogg::ModuleUtils::NidhoggETWBypass" nocase ascii wide
                        $string36 = "Nidhogg::ModuleUtils::NidhoggInjectDll" nocase ascii wide
                        $string37 = "Nidhogg::ModuleUtils::NidhoggInjectShellcode" nocase ascii wide
                        $string38 = "Nidhogg::ModuleUtils::NidhoggPatchModule" nocase ascii wide
                        $string39 = "Nidhogg::ModuleUtils::NidhoggReadData" nocase ascii wide
                        $string40 = "Nidhogg::ModuleUtils::NidhoggWriteData" nocase ascii wide
                        $string41 = "Nidhogg::ProcessUtils::NidhoggProcessClearAllProtection" nocase ascii wide
                        $string42 = "Nidhogg::ProcessUtils::NidhoggProcessElevate" nocase ascii wide
                        $string43 = "Nidhogg::ProcessUtils::NidhoggProcessHide" nocase ascii wide
                        $string44 = "Nidhogg::ProcessUtils::NidhoggProcessProtect" nocase ascii wide
                        $string45 = "Nidhogg::ProcessUtils::NidhoggProcessSetProtection" nocase ascii wide
                        $string46 = "Nidhogg::ProcessUtils::NidhoggProcessUnhide" nocase ascii wide
                        $string47 = "Nidhogg::ProcessUtils::NidhoggProcessUnprotect" nocase ascii wide
                        $string48 = "Nidhogg::ProcessUtils::NidhoggQueryProcesses" nocase ascii wide
                        $string49 = "Nidhogg::ProcessUtils::NidhoggQueryThreads" nocase ascii wide
                        $string50 = "Nidhogg::ProcessUtils::NidhoggThreadHide" nocase ascii wide
                        $string51 = "Nidhogg::ProcessUtils::NidhoggThreadProtect" nocase ascii wide
                        $string52 = "Nidhogg::RegistryUtils::NidhoggRegistryClearAll" nocase ascii wide
                        $string53 = "Nidhogg::RegistryUtils::NidhoggRegistryHideKey" nocase ascii wide
                        $string54 = "Nidhogg::RegistryUtils::NidhoggRegistryHideValue" nocase ascii wide
                        $string55 = "Nidhogg::RegistryUtils::NidhoggRegistryProtectKey" nocase ascii wide
                        $string56 = "Nidhogg::RegistryUtils::NidhoggRegistryProtectValue" nocase ascii wide
                        $string57 = "Nidhogg::RegistryUtils::NidhoggRegistryQueryHiddenKeys" nocase ascii wide
                        $string58 = "Nidhogg::RegistryUtils::NidhoggRegistryQueryHiddenValues" nocase ascii wide
                        $string59 = "Nidhogg::RegistryUtils::NidhoggRegistryQueryProtectedKeys" nocase ascii wide
                        $string60 = "Nidhogg::RegistryUtils::NidhoggRegistryQueryProtectedValues" nocase ascii wide
                        $string61 = "Nidhogg::RegistryUtils::NidhoggRegistryUnhideKey" nocase ascii wide
                        $string62 = "Nidhogg::RegistryUtils::NidhoggRegistryUnhideValue" nocase ascii wide
                        $string63 = "Nidhogg::RegistryUtils::NidhoggRegistryUnprotectValue" nocase ascii wide
                        $string64 = /Nidhogg\-0\.1\.zip/ nocase ascii wide
                        $string65 = /Nidhogg\-0\.2\.zip/ nocase ascii wide
                        $string66 = /Nidhogg\-0\.3\.zip/ nocase ascii wide
                        $string67 = /Nidhogg\-0\.4\.zip/ nocase ascii wide
                        $string68 = /Nidhogg\-0\.5\.zip/ nocase ascii wide
                        $string69 = /NidhoggClient\.exe\s/ nocase ascii wide
                        $string70 = /NidhoggExample\.cpp/ nocase ascii wide
                        $string71 = "Nidhogg-master" nocase ascii wide
                        $string72 = "sc start nidhogg" nocase ascii wide
                        $string73 = /tNidhoggClient\.exe/ nocase ascii wide

    condition:
        any of them
}