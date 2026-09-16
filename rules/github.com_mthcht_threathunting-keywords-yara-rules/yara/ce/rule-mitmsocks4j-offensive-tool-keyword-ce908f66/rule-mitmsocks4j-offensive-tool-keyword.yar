rule rule_mitmsocks4j_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mitmsocks4j' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mitmsocks4j"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mitmsocks4j_offensive_tool_keyword = "mitmsocks" nocase ascii wide
                        $string2_mitmsocks4j_offensive_tool_keyword = "mitmsocks4j" nocase ascii wide

    condition:
        any of them
}