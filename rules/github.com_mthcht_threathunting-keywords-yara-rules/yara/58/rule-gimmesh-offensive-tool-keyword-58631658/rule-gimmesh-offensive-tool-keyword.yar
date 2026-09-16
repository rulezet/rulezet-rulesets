rule rule_gimmeSH_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gimmeSH' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gimmeSH"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gimmeSH_offensive_tool_keyword = /\.\/gimmeSH/
                        $string2_gimmeSH_offensive_tool_keyword = /\/gimmeSH\.sh/ nocase ascii wide
                        $string3_gimmeSH_offensive_tool_keyword = "A3h1nt/gimmeSH" nocase ascii wide

    condition:
        any of them
}