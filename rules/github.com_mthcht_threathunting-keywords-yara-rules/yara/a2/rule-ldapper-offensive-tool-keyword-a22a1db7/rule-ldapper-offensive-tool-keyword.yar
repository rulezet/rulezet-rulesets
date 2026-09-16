rule rule_LDAPPER_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LDAPPER' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LDAPPER"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LDAPPER_offensive_tool_keyword = /\sldapper\.py/ nocase ascii wide
                        $string2_LDAPPER_offensive_tool_keyword = /\/LDAPPER\.git/ nocase ascii wide
                        $string3_LDAPPER_offensive_tool_keyword = /\/ldapper\.py/ nocase ascii wide
                        $string4_LDAPPER_offensive_tool_keyword = "/LDAPPER-master" nocase ascii wide
                        $string5_LDAPPER_offensive_tool_keyword = /\\ldapper\.py/ nocase ascii wide
                        $string6_LDAPPER_offensive_tool_keyword = /\\LDAPPER\-master/ nocase ascii wide
                        $string7_LDAPPER_offensive_tool_keyword = /AD\sLDAP\sCommand\sLine\sSearching\sthat\sdoesn\'t\ssuck\./ nocase ascii wide
                        $string8_LDAPPER_offensive_tool_keyword = "shellster/LDAPPER" nocase ascii wide

    condition:
        any of them
}