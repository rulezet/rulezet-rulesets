rule mitmsocks4j
{
    meta:
        description = "Detection patterns for the tool 'mitmsocks4j' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mitmsocks4j"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "mitmsocks" nocase ascii wide
                        $string2 = "mitmsocks4j" nocase ascii wide

    condition:
        any of them
}