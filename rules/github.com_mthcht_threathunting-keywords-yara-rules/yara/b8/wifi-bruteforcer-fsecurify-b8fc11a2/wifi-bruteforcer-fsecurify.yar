rule wifi_bruteforcer_fsecurify
{
    meta:
        description = "Detection patterns for the tool 'wifi-bruteforcer-fsecurify' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifi-bruteforcer-fsecurify"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "wifi-bruteforcer" nocase ascii wide

    condition:
        any of them
}