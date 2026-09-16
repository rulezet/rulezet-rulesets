rule kali_anonsurf
{
    meta:
        description = "Detection patterns for the tool 'kali-anonsurf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kali-anonsurf"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "kali-anonsurf"

    condition:
        any of them
}