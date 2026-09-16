rule rule_kismet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'kismet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kismet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_kismet_offensive_tool_keyword = "/kismet"
                        $string2_kismet_offensive_tool_keyword = "/kismetwireless/" nocase ascii wide

    condition:
        any of them
}