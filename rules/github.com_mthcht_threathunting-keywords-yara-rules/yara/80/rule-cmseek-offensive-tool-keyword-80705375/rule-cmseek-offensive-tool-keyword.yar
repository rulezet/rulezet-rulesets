rule rule_CMSeek_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CMSeek' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CMSeek"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CMSeek_offensive_tool_keyword = "/CMSeek" nocase ascii wide

    condition:
        any of them
}