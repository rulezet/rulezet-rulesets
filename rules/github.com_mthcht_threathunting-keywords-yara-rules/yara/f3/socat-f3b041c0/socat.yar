rule socat
{
    meta:
        description = "Detection patterns for the tool 'socat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "socat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "socat tcp4-listen:1337"

    condition:
        any of them
}