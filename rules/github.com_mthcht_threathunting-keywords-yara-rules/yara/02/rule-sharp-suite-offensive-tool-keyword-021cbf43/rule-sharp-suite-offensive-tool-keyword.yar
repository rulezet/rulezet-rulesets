rule rule_Sharp_Suite_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Sharp-Suite' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sharp-Suite"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Sharp_Suite_offensive_tool_keyword = "FuzzySecurity/Sharp-Suite" nocase ascii wide
                        $string2_Sharp_Suite_offensive_tool_keyword = /Londor\.exe\s\-t\sCoverage/ nocase ascii wide
                        $string3_Sharp_Suite_offensive_tool_keyword = /Londor\.exe\s\-t\sScript/ nocase ascii wide
                        $string4_Sharp_Suite_offensive_tool_keyword = /Sharp\-Suite\.git/ nocase ascii wide
                        $string5_Sharp_Suite_offensive_tool_keyword = /UrbanBishop\.exe/ nocase ascii wide

    condition:
        any of them
}