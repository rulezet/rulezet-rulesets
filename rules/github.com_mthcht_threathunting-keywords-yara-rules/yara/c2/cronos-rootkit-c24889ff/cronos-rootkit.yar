rule Cronos_Rootkit
{
    meta:
        description = "Detection patterns for the tool 'Cronos-Rootkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cronos-Rootkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "- Cronos rootkit debugger -" nocase ascii wide
                        $string2 = "/Cronos-Rootkit" nocase ascii wide
                        $string3 = "/Cronos-Rootkit/" nocase ascii wide
                        $string4 = /\/Cronos\-x64\.zip/ nocase ascii wide
                        $string5 = /\\\\\\\\\.\\\\Cronos/ nocase ascii wide
                        $string6 = /\\Cronos\sRootkit\.sln/ nocase ascii wide
                        $string7 = /\\Cronos\sRootkit\\/ nocase ascii wide
                        $string8 = /\\CronosDebugger\.vcxproj/ nocase ascii wide
                        $string9 = /\\Cronos\-x64\.zip/ nocase ascii wide
                        $string10 = /\\Rootkit\.cpp/ nocase ascii wide
                        $string11 = "05B4EB7F-3D59-4E6A-A7BC-7C1241578CA7" nocase ascii wide
                        $string12 = "1d9b4121c2dbc17a4db31341da2097cd430a61201c57185a42fb687f22f704eb" nocase ascii wide
                        $string13 = "6f7949ffcf1b9bce2ab2301e6a75a4ba8690ea3434b74bd6c3ba0e9aca6d5d04" nocase ascii wide
                        $string14 = "940B1177-2B8C-48A2-A8E7-BF4E8E80C60F" nocase ascii wide
                        $string15 = /Cronos\sRootkit\./ nocase ascii wide
                        $string16 = /CronosDebugger\./ nocase ascii wide
                        $string17 = /CronosRootkit\./ nocase ascii wide
                        $string18 = /Rootkit\.cpp/ nocase ascii wide

    condition:
        any of them
}