rule rule__base64_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'base64' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "base64"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1__base64_offensive_tool_keyword = "QW1zaVNjYW5CdWZmZXI=" nocase ascii wide
                        $string2__base64_offensive_tool_keyword = "TVqQAAMAAAAEAAAA" nocase ascii wide

    condition:
        any of them
}