rule rule_metagoofil_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'metagoofil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "metagoofil"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_metagoofil_offensive_tool_keyword = "metagoofil" nocase ascii wide

    condition:
        any of them
}