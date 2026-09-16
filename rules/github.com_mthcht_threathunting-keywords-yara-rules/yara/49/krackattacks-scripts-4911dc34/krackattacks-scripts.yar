rule krackattacks_scripts
{
    meta:
        description = "Detection patterns for the tool 'krackattacks-scripts' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "krackattacks-scripts"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "krackattacks" nocase ascii wide

    condition:
        any of them
}