rule rule_Timeroast_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Timeroast' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Timeroast"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Timeroast_offensive_tool_keyword = /extra\-scripts.{0,1000}timecrack\.py/ nocase ascii wide
                        $string2_Timeroast_offensive_tool_keyword = /kirbi_to_hashcat\.py/ nocase ascii wide
                        $string3_Timeroast_offensive_tool_keyword = /timeroast\.ps1/ nocase ascii wide
                        $string4_Timeroast_offensive_tool_keyword = /timeroast\.py/ nocase ascii wide

    condition:
        any of them
}