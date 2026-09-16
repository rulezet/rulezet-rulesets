rule rule_sslstrip_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sslstrip' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sslstrip"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sslstrip_offensive_tool_keyword = "sslstrip" nocase ascii wide

    condition:
        any of them
}