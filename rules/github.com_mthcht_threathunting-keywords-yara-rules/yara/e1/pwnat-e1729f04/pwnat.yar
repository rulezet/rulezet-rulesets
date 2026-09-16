rule pwnat
{
    meta:
        description = "Detection patterns for the tool 'pwnat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwnat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /pwnat\.exe/ nocase ascii wide

    condition:
        any of them
}