rule shodan_io
{
    meta:
        description = "Detection patterns for the tool 'shodan.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shodan.io"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /Shodan\.io/ nocase ascii wide

    condition:
        any of them
}