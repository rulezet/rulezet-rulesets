rule rule__base64_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'base64' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "base64"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1__base64_greyware_tool_keyword = /\|\sbase64\s\-d\s/ nocase ascii wide
                        $string2__base64_greyware_tool_keyword = "base64 -d /tmp/" nocase ascii wide

    condition:
        any of them
}