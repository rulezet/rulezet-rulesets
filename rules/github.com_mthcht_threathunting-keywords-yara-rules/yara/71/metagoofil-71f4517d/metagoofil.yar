rule metagoofil
{
    meta:
        description = "Detection patterns for the tool 'metagoofil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "metagoofil"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "metagoofil" nocase ascii wide

    condition:
        any of them
}