rule rule_Awesome_Hacking_Resources_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Awesome-Hacking-Resources' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Awesome-Hacking-Resources"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Awesome_Hacking_Resources_offensive_tool_keyword = "Awesome-Hacking-Resources" nocase ascii wide

    condition:
        any of them
}