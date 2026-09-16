rule rule_Oh365UserFinder_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Oh365UserFinder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Oh365UserFinder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Oh365UserFinder_offensive_tool_keyword = "/Oh365UserFinder" nocase ascii wide
                        $string2_Oh365UserFinder_offensive_tool_keyword = /Oh365UserFinder\.git/ nocase ascii wide
                        $string3_Oh365UserFinder_offensive_tool_keyword = /oh365userfinder\.py/ nocase ascii wide
                        $string4_Oh365UserFinder_offensive_tool_keyword = "Oh365UserFinder-main" nocase ascii wide

    condition:
        any of them
}