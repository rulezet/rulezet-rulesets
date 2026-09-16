rule rule_wifi_bruteforcer_fsecurity_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wifi-bruteforcer-fsecurity' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifi-bruteforcer-fsecurity"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wifi_bruteforcer_fsecurity_offensive_tool_keyword = "wifi-bruteforcer" nocase ascii wide

    condition:
        any of them
}