rule rule_combine_harvester_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'combine_harvester' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "combine_harvester"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_combine_harvester_offensive_tool_keyword = /\/combine_harvester\.git/ nocase ascii wide
                        $string2_combine_harvester_offensive_tool_keyword = /\[X\]\sYour\sharvest\sexploded\:/ nocase ascii wide
                        $string3_combine_harvester_offensive_tool_keyword = /\\combine\.exe/ nocase ascii wide
                        $string4_combine_harvester_offensive_tool_keyword = /\\combine_gui\.exe/ nocase ascii wide
                        $string5_combine_harvester_offensive_tool_keyword = /\\harvest\.cmb/ nocase ascii wide
                        $string6_combine_harvester_offensive_tool_keyword = "23E06BF12C5BE7641EF89F557C3F6600E1F3881F8DCE7279C2112279E7EC3B988E1A85EC350149007DE78CE5566FCBD18F630D2CDB78C76AA06F2B121F0B3701" nocase ascii wide
                        $string7_combine_harvester_offensive_tool_keyword = "combine_harvester-main" nocase ascii wide
                        $string8_combine_harvester_offensive_tool_keyword = "m3f157O/combine_harvester" nocase ascii wide

    condition:
        any of them
}