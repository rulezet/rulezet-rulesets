rule rule_OSCP_Archives_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OSCP-Archives' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OSCP-Archives"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_OSCP_Archives_offensive_tool_keyword = "OSCP-Archives" nocase ascii wide
                        $string2_OSCP_Archives_offensive_tool_keyword = /scecli\\0evilpwfilter/ nocase ascii wide

    condition:
        any of them
}