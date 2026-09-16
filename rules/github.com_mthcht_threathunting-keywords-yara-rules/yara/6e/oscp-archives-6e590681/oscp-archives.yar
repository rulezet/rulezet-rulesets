rule OSCP_Archives
{
    meta:
        description = "Detection patterns for the tool 'OSCP-Archives' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OSCP-Archives"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "OSCP-Archives" nocase ascii wide
                        $string2 = /scecli\\0evilpwfilter/ nocase ascii wide

    condition:
        any of them
}