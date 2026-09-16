rule rule_kali_anonsurf_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'kali-anonsurf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kali-anonsurf"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_kali_anonsurf_offensive_tool_keyword = "kali-anonsurf"

    condition:
        any of them
}