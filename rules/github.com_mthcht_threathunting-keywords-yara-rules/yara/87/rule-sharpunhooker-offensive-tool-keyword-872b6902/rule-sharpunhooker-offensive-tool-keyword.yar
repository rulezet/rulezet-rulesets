rule rule_SharpUnhooker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpUnhooker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpUnhooker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpUnhooker_offensive_tool_keyword = /\/SharpUnhooker\.git/ nocase ascii wide
                        $string2_SharpUnhooker_offensive_tool_keyword = "GetRektBoy724/SharpUnhooker" nocase ascii wide
                        $string3_SharpUnhooker_offensive_tool_keyword = /SharpUnhooker\./ nocase ascii wide
                        $string4_SharpUnhooker_offensive_tool_keyword = "SharpUnhooker-main" nocase ascii wide

    condition:
        any of them
}