rule DumpCreds
{
    meta:
        description = "Detection patterns for the tool 'DumpCreds' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpCreds"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "DumpCreds" nocase ascii wide

    condition:
        any of them
}