rule rule_Whisker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Whisker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Whisker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Whisker_offensive_tool_keyword = " is a C# tool for taking over Active Directory user and computer accounts by manipulating their " nocase ascii wide
                        $string2_Whisker_offensive_tool_keyword = /\/Whisker\.exe/ nocase ascii wide
                        $string3_Whisker_offensive_tool_keyword = /\\Whisker\.exe/ nocase ascii wide
                        $string4_Whisker_offensive_tool_keyword = /\\Whisker\.pdb/ nocase ascii wide
                        $string5_Whisker_offensive_tool_keyword = /Whisker\.DSInternals\./ nocase ascii wide

    condition:
        any of them
}