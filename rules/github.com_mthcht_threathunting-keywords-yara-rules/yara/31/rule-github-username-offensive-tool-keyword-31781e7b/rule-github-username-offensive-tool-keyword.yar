rule rule_Github_Username_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Github Username' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Github Username"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Github_Username_offensive_tool_keyword = "/attackercan/" nocase ascii wide
                        $string2_Github_Username_offensive_tool_keyword = "/Ben0xA/" nocase ascii wide
                        $string3_Github_Username_offensive_tool_keyword = "BastilleResearch" nocase ascii wide
                        $string4_Github_Username_offensive_tool_keyword = "BC-SECURITY" nocase ascii wide
                        $string5_Github_Username_offensive_tool_keyword = /guardicore.{0,1000}monkey/ nocase ascii wide
                        $string6_Github_Username_offensive_tool_keyword = "s7scan" nocase ascii wide

    condition:
        any of them
}