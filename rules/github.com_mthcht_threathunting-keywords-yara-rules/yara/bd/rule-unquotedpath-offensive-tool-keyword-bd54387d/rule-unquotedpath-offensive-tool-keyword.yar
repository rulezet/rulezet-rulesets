rule rule_UnquotedPath_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'UnquotedPath' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnquotedPath"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_UnquotedPath_offensive_tool_keyword = "master/UnquotedPath" nocase ascii wide
                        $string2_UnquotedPath_offensive_tool_keyword = /UnquotedPath\.csproj/ nocase ascii wide
                        $string3_UnquotedPath_offensive_tool_keyword = /UnquotedPath\.exe/ nocase ascii wide

    condition:
        any of them
}