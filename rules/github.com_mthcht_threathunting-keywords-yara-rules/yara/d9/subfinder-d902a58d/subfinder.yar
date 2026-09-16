rule subfinder
{
    meta:
        description = "Detection patterns for the tool 'subfinder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "subfinder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "subfinder" nocase ascii wide

    condition:
        any of them
}