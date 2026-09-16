rule rule_dtd_finder_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dtd-finder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dtd-finder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dtd_finder_offensive_tool_keyword = "dtd-finder" nocase ascii wide

    condition:
        any of them
}