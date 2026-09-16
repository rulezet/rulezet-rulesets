rule rule_Ahk2Exe_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ahk2Exe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ahk2Exe"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Ahk2Exe_greyware_tool_keyword = /\sAhk2Exe\.exe/ nocase ascii wide
                        $string2_Ahk2Exe_greyware_tool_keyword = /\/Ahk2Exe\.exe/ nocase ascii wide
                        $string3_Ahk2Exe_greyware_tool_keyword = /\/Ahk2Exe\.git/ nocase ascii wide
                        $string4_Ahk2Exe_greyware_tool_keyword = /\/Ahk2Exe\.zip/ nocase ascii wide
                        $string5_Ahk2Exe_greyware_tool_keyword = /\/Ahk2Exe1\..{0,1000}\.zip/ nocase ascii wide
                        $string6_Ahk2Exe_greyware_tool_keyword = /\/ahk\-install\.exe/ nocase ascii wide
                        $string7_Ahk2Exe_greyware_tool_keyword = /\/ahk\-v2\.exe/ nocase ascii wide
                        $string8_Ahk2Exe_greyware_tool_keyword = /\/AutoHotkey_1.{0,1000}_setup\.exe/ nocase ascii wide
                        $string9_Ahk2Exe_greyware_tool_keyword = /\/AutoHotkey_2.{0,1000}_setup\.exe/ nocase ascii wide
                        $string10_Ahk2Exe_greyware_tool_keyword = /\/AutoHotkey64\.exe/ nocase ascii wide
                        $string11_Ahk2Exe_greyware_tool_keyword = "/releases/download/Ahk2Exe" nocase ascii wide
                        $string12_Ahk2Exe_greyware_tool_keyword = /\\Ahk2Exe\.ahk/ nocase ascii wide
                        $string13_Ahk2Exe_greyware_tool_keyword = /\\Ahk2Exe\.exe/ nocase ascii wide
                        $string14_Ahk2Exe_greyware_tool_keyword = /\\Ahk2Exe\.zip/ nocase ascii wide
                        $string15_Ahk2Exe_greyware_tool_keyword = /\\AutoHotkey_1.{0,1000}_setup\.exe/ nocase ascii wide
                        $string16_Ahk2Exe_greyware_tool_keyword = /\\AutoHotkey_2.{0,1000}_setup\.exe/ nocase ascii wide
                        $string17_Ahk2Exe_greyware_tool_keyword = /\\AutoHotkey64\.exe/ nocase ascii wide
                        $string18_Ahk2Exe_greyware_tool_keyword = /\\AutoHotkey64_UIA\.exe/ nocase ascii wide
                        $string19_Ahk2Exe_greyware_tool_keyword = /\\AutoHotkeySC\.bin/ nocase ascii wide
                        $string20_Ahk2Exe_greyware_tool_keyword = /\\AutoHotkeyU32\.exe/ nocase ascii wide
                        $string21_Ahk2Exe_greyware_tool_keyword = /\\AutoHotkeyUX\.exe/ nocase ascii wide
                        $string22_Ahk2Exe_greyware_tool_keyword = /\\Program\sFiles\\AutoHotkey/ nocase ascii wide
                        $string23_Ahk2Exe_greyware_tool_keyword = /\\SetExeSubsystem\.ahk/ nocase ascii wide
                        $string24_Ahk2Exe_greyware_tool_keyword = /\\SOFTWARE\\Classes\\\.ahk\\/ nocase ascii wide
                        $string25_Ahk2Exe_greyware_tool_keyword = /\\SOFTWARE\\Classes\\AutoHotkeyScript\\/ nocase ascii wide
                        $string26_Ahk2Exe_greyware_tool_keyword = /\\UX\\reset\-assoc\.ahk/ nocase ascii wide
                        $string27_Ahk2Exe_greyware_tool_keyword = ">AutoHotkey installer<" nocase ascii wide
                        $string28_Ahk2Exe_greyware_tool_keyword = ">AutoHotkey Setup<" nocase ascii wide
                        $string29_Ahk2Exe_greyware_tool_keyword = "14a8b1ff0297c5f7c06c6ab36a257140c2f3d33e8c15a28e790d5039a29c00a7" nocase ascii wide
                        $string30_Ahk2Exe_greyware_tool_keyword = "41092e2433211a876f2b14f16a29fdae85a0d7e74565b23ab9e9c85bee892351" nocase ascii wide
                        $string31_Ahk2Exe_greyware_tool_keyword = "46d335c6ebda027aea00f5a8261b4d1a1763e17b858fe512bbe541f9bb66d464" nocase ascii wide
                        $string32_Ahk2Exe_greyware_tool_keyword = "4e1e3123dd85d3ac65a0803b08dd89b9b12b5a00b9f566782855332d03e5fe26" nocase ascii wide
                        $string33_Ahk2Exe_greyware_tool_keyword = "4f30ed7899506d15974d12e428f4647660f97a52cc21da06a6a295a06197bbd8" nocase ascii wide
                        $string34_Ahk2Exe_greyware_tool_keyword = "7a2aeb7256c40efa434c6fc95f920ee9b4555e526f2f7cd325b6dc482faa7c20" nocase ascii wide
                        $string35_Ahk2Exe_greyware_tool_keyword = "80840379e83b70528c541218023961323ae10cfd85b4a1dcf6bf0fc01a9336b7" nocase ascii wide
                        $string36_Ahk2Exe_greyware_tool_keyword = "80ce06d9341317b4c4b4b1e89b2f046e0426e1e952eaa9152231cc26a08de58f" nocase ascii wide
                        $string37_Ahk2Exe_greyware_tool_keyword = "9f2c7f990c554ba286616dd08e59ac32d543e80eef335f5c65762c020234bc1b" nocase ascii wide
                        $string38_Ahk2Exe_greyware_tool_keyword = "ab464ef9bfa3735111e4fbf0e21f34feecf29a66d8effce37814df6be1d8314b" nocase ascii wide
                        $string39_Ahk2Exe_greyware_tool_keyword = "AutoHotkey/Ahk2Exe" nocase ascii wide
                        $string40_Ahk2Exe_greyware_tool_keyword = /https\:\/\/www\.autohotkey\.com\/download\// nocase ascii wide
                        $string41_Ahk2Exe_greyware_tool_keyword = /s\\AutoHotkey\sWindow\sSpy\.lnk/ nocase ascii wide

    condition:
        any of them
}