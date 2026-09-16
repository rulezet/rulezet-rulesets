rule wafw00f
{
    meta:
        description = "Detection patterns for the tool 'wafw00f' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wafw00f"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "wafw00f" nocase ascii wide

    condition:
        any of them
}