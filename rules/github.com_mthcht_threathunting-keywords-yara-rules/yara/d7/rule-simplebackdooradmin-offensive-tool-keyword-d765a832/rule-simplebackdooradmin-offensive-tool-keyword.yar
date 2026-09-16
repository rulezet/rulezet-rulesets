rule rule_SimpleBackdoorAdmin_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SimpleBackdoorAdmin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SimpleBackdoorAdmin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SimpleBackdoorAdmin_offensive_tool_keyword = "net localgroup administrators backdoor" nocase ascii wide
                        $string2_SimpleBackdoorAdmin_offensive_tool_keyword = "net user backdoor Password123!" nocase ascii wide
                        $string3_SimpleBackdoorAdmin_offensive_tool_keyword = /SimpleBackdoorAdmin\.dll/ nocase ascii wide
                        $string4_SimpleBackdoorAdmin_offensive_tool_keyword = /SimpleBackdoorAdmin\.exe/ nocase ascii wide

    condition:
        any of them
}