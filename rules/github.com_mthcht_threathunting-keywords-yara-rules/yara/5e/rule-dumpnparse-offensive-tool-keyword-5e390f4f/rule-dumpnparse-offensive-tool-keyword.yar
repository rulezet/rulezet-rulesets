rule rule_DumpNParse_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DumpNParse' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpNParse"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DumpNParse_offensive_tool_keyword = /\/DumpNParse\.exe/ nocase ascii wide
                        $string2_DumpNParse_offensive_tool_keyword = /\/DumpNParse\.git/ nocase ascii wide
                        $string3_DumpNParse_offensive_tool_keyword = /\\\\windows\\\\temp\\\\lsass\.dmp/ nocase ascii wide
                        $string4_DumpNParse_offensive_tool_keyword = /\\DumpNParse\.exe/ nocase ascii wide
                        $string5_DumpNParse_offensive_tool_keyword = /\\DumpNParse\-main/ nocase ascii wide
                        $string6_DumpNParse_offensive_tool_keyword = "BA1F3992-9654-4424-A0CC-26158FDFBF74" nocase ascii wide
                        $string7_DumpNParse_offensive_tool_keyword = /C\:\\Users\\.{0,1000}\\lsass_.{0,1000}\.dmp/ nocase ascii wide
                        $string8_DumpNParse_offensive_tool_keyword = /DumpNParse\-main\.zip/ nocase ascii wide
                        $string9_DumpNParse_offensive_tool_keyword = "f038fdbc3ed50ebbf1ebc1c814836bcf93b4c149e5856ccf9b5400da8a974117" nocase ascii wide
                        $string10_DumpNParse_offensive_tool_keyword = "icyguider/DumpNParse" nocase ascii wide
                        $string11_DumpNParse_offensive_tool_keyword = "lsass dump saved to: " nocase ascii wide
                        $string12_DumpNParse_offensive_tool_keyword = /Program\.MiniDump\sminidump/ nocase ascii wide

    condition:
        any of them
}