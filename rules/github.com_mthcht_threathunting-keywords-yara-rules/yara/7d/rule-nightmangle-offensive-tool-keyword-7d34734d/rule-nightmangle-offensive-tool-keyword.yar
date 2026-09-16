rule rule_Nightmangle_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Nightmangle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nightmangle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Nightmangle_offensive_tool_keyword = /\/imperun\s.{0,1000}\s.{0,1000}cmd\.exe\s\/c\swhoami/ nocase ascii wide
                        $string2_Nightmangle_offensive_tool_keyword = /\/Nightmangle\.git/ nocase ascii wide
                        $string3_Nightmangle_offensive_tool_keyword = /\[\+\]\sBof\sreplay\:/ nocase ascii wide
                        $string4_Nightmangle_offensive_tool_keyword = /\[\+\]\sSeImpersonatePrivilege\senabled/ nocase ascii wide
                        $string5_Nightmangle_offensive_tool_keyword = "1N73LL1G3NC3x/Nightmangle" nocase ascii wide
                        $string6_Nightmangle_offensive_tool_keyword = "BeaconInjectProcess" nocase ascii wide
                        $string7_Nightmangle_offensive_tool_keyword = "BeaconInjectTemporaryProcess" nocase ascii wide
                        $string8_Nightmangle_offensive_tool_keyword = "Nightmangle-master" nocase ascii wide

    condition:
        any of them
}