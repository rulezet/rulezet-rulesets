rule rule_MDExclusionParser_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MDExclusionParser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MDExclusionParser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MDExclusionParser_offensive_tool_keyword = /\sInvoke\-MDExclusionParser\.ps1/ nocase ascii wide
                        $string2_MDExclusionParser_offensive_tool_keyword = /\/Invoke\-MDExclusionParser\.ps1/ nocase ascii wide
                        $string3_MDExclusionParser_offensive_tool_keyword = /\/MDExclusionParser\.git/ nocase ascii wide
                        $string4_MDExclusionParser_offensive_tool_keyword = /\[i\]\sParsing\sfor\sDefender\sExclusions/ nocase ascii wide
                        $string5_MDExclusionParser_offensive_tool_keyword = /\\Invoke\-MDExclusionParser\.ps1/ nocase ascii wide
                        $string6_MDExclusionParser_offensive_tool_keyword = "Invoke-MDExclusionParser " nocase ascii wide
                        $string7_MDExclusionParser_offensive_tool_keyword = "MDExclusionParser-main" nocase ascii wide
                        $string8_MDExclusionParser_offensive_tool_keyword = "ViziosDe/MDExclusionParser" nocase ascii wide

    condition:
        any of them
}