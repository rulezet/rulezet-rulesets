rule kismet
{
    meta:
        description = "Detection patterns for the tool 'kismet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kismet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/kismet"
                        $string2 = "/kismetwireless/" nocase ascii wide

    condition:
        any of them
}