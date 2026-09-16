rule PSByPassCLM
{
    meta:
        description = "Detection patterns for the tool 'PSByPassCLM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSByPassCLM"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "PSByPassCLM" nocase ascii wide

    condition:
        any of them
}