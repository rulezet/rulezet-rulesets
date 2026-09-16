rule rule_FindUncommonShares_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FindUncommonShares' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FindUncommonShares"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FindUncommonShares_offensive_tool_keyword = /\-\-dc\-ip\s.{0,1000}\-\-check\-user\-access/ nocase ascii wide
                        $string2_FindUncommonShares_offensive_tool_keyword = /FindUncommonShares\.git/ nocase ascii wide
                        $string3_FindUncommonShares_offensive_tool_keyword = /FindUncommonShares\.py\s/ nocase ascii wide
                        $string4_FindUncommonShares_offensive_tool_keyword = "FindUncommonShares-main" nocase ascii wide

    condition:
        any of them
}