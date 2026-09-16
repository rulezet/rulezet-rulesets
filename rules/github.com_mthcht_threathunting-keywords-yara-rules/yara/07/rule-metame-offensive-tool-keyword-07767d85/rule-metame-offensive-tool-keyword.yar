rule rule_metame_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'metame' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "metame"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_metame_offensive_tool_keyword = "a0rtega/metame" nocase ascii wide
                        $string2_metame_offensive_tool_keyword = "import metame" nocase ascii wide
                        $string3_metame_offensive_tool_keyword = /metame\s\-i\s.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}