rule rule_TrueSocks_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TrueSocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TrueSocks"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TrueSocks_offensive_tool_keyword = /\/truesocks_rs\.git/ nocase ascii wide
                        $string2_TrueSocks_offensive_tool_keyword = /api\.truesocks\.net/ nocase ascii wide
                        $string3_TrueSocks_offensive_tool_keyword = "c0dn/truesocks_rs" nocase ascii wide

    condition:
        any of them
}