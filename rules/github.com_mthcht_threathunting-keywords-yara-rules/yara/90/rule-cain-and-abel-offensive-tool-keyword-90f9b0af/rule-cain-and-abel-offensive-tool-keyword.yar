rule rule_Cain_and_Abel_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Cain&Abel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cain&Abel"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Cain_and_Abel_offensive_tool_keyword = /\/cain\.html/ nocase ascii wide

    condition:
        any of them
}