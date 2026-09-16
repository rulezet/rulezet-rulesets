rule rule_dirscraper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dirscraper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirscraper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dirscraper_offensive_tool_keyword = "dirscraper" nocase ascii wide

    condition:
        any of them
}