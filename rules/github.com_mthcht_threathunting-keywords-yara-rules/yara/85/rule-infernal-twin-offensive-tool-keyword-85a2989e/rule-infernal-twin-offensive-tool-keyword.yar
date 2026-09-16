rule rule_infernal_twin_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'infernal-twin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "infernal-twin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_infernal_twin_offensive_tool_keyword = /1337.{0,1000}infernal\-twin/ nocase ascii wide

    condition:
        any of them
}