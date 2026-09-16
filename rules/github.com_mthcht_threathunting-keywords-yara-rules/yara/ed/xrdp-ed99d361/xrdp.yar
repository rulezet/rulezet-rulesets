rule xrdp
{
    meta:
        description = "Detection patterns for the tool 'xrdp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xrdp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /xrdp\.c/ nocase ascii wide

    condition:
        any of them
}