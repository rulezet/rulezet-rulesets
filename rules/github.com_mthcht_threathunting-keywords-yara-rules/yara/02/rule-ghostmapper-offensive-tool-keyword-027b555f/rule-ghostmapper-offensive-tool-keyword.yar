rule rule_GhostMapper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GhostMapper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostMapper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GhostMapper_offensive_tool_keyword = /\/GhostMapper\.git/ nocase ascii wide
                        $string2_GhostMapper_offensive_tool_keyword = /\/GhostMapper\.sln/ nocase ascii wide
                        $string3_GhostMapper_offensive_tool_keyword = /\\GhostMapper\.sln/ nocase ascii wide
                        $string4_GhostMapper_offensive_tool_keyword = "4D7BA537-54EC-4005-9CC2-AE134B4526F9" nocase ascii wide
                        $string5_GhostMapper_offensive_tool_keyword = /GhostMapper\-main\./ nocase ascii wide
                        $string6_GhostMapper_offensive_tool_keyword = "Oliver-1-1/GhostMapper" nocase ascii wide

    condition:
        any of them
}