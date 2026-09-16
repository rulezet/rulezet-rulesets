rule rule_BlockOpenHandle_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BlockOpenHandle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlockOpenHandle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BlockOpenHandle_offensive_tool_keyword = /\/BlockOpenHandle\.git/ nocase ascii wide
                        $string2_BlockOpenHandle_offensive_tool_keyword = "55F0368B-63DA-40E7-A8A5-289F70DF9C7F" nocase ascii wide
                        $string3_BlockOpenHandle_offensive_tool_keyword = /BlockOpenHandle\.cpp/ nocase ascii wide
                        $string4_BlockOpenHandle_offensive_tool_keyword = /BlockOpenHandle\.exe/ nocase ascii wide
                        $string5_BlockOpenHandle_offensive_tool_keyword = /BlockOpenHandle\.vcxproj/ nocase ascii wide
                        $string6_BlockOpenHandle_offensive_tool_keyword = "BlockOpenHandle-main" nocase ascii wide

    condition:
        any of them
}