rule rule_rdpscraper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rdpscraper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdpscraper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rdpscraper_offensive_tool_keyword = "rdpscraper" nocase ascii wide

    condition:
        any of them
}