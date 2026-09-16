rule rule_Cronos_Rootkit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Cronos-Rootkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cronos-Rootkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Cronos_Rootkit_offensive_tool_keyword = "- Cronos rootkit debugger -" nocase ascii wide
                        $string2_Cronos_Rootkit_offensive_tool_keyword = "/Cronos-Rootkit" nocase ascii wide
                        $string3_Cronos_Rootkit_offensive_tool_keyword = "/Cronos-Rootkit/" nocase ascii wide
                        $string4_Cronos_Rootkit_offensive_tool_keyword = /\/Cronos\-x64\.zip/ nocase ascii wide
                        $string5_Cronos_Rootkit_offensive_tool_keyword = /\\\\\\\\\.\\\\Cronos/ nocase ascii wide
                        $string6_Cronos_Rootkit_offensive_tool_keyword = /\\Cronos\sRootkit\.sln/ nocase ascii wide
                        $string7_Cronos_Rootkit_offensive_tool_keyword = /\\Cronos\sRootkit\\/ nocase ascii wide
                        $string8_Cronos_Rootkit_offensive_tool_keyword = /\\CronosDebugger\.vcxproj/ nocase ascii wide
                        $string9_Cronos_Rootkit_offensive_tool_keyword = /\\Cronos\-x64\.zip/ nocase ascii wide
                        $string10_Cronos_Rootkit_offensive_tool_keyword = /\\Rootkit\.cpp/ nocase ascii wide
                        $string11_Cronos_Rootkit_offensive_tool_keyword = "05B4EB7F-3D59-4E6A-A7BC-7C1241578CA7" nocase ascii wide
                        $string12_Cronos_Rootkit_offensive_tool_keyword = "1d9b4121c2dbc17a4db31341da2097cd430a61201c57185a42fb687f22f704eb" nocase ascii wide
                        $string13_Cronos_Rootkit_offensive_tool_keyword = "6f7949ffcf1b9bce2ab2301e6a75a4ba8690ea3434b74bd6c3ba0e9aca6d5d04" nocase ascii wide
                        $string14_Cronos_Rootkit_offensive_tool_keyword = "940B1177-2B8C-48A2-A8E7-BF4E8E80C60F" nocase ascii wide
                        $string15_Cronos_Rootkit_offensive_tool_keyword = /Cronos\sRootkit\./ nocase ascii wide
                        $string16_Cronos_Rootkit_offensive_tool_keyword = /CronosDebugger\./ nocase ascii wide
                        $string17_Cronos_Rootkit_offensive_tool_keyword = /CronosRootkit\./ nocase ascii wide
                        $string18_Cronos_Rootkit_offensive_tool_keyword = /Rootkit\.cpp/ nocase ascii wide

    condition:
        any of them
}