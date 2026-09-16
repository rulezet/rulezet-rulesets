rule rule_MSDAT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MSDAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MSDAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MSDAT_offensive_tool_keyword = /quentinhardy.{0,1000}msdat/ nocase ascii wide

    condition:
        any of them
}