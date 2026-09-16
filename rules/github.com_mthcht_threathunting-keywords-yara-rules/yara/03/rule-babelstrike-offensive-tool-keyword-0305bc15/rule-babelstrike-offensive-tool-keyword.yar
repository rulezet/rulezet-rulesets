rule rule_BabelStrike_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BabelStrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BabelStrike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BabelStrike_offensive_tool_keyword = /\sBabelStrike\.py/ nocase ascii wide
                        $string2_BabelStrike_offensive_tool_keyword = /\/BabelStrike\.git/ nocase ascii wide
                        $string3_BabelStrike_offensive_tool_keyword = /\/BabelStrike\.py/ nocase ascii wide
                        $string4_BabelStrike_offensive_tool_keyword = /\\BabelStrike\.py/ nocase ascii wide
                        $string5_BabelStrike_offensive_tool_keyword = /babelstrike\.py\s\-/ nocase ascii wide
                        $string6_BabelStrike_offensive_tool_keyword = "BabelStrike-main" nocase ascii wide
                        $string7_BabelStrike_offensive_tool_keyword = "t3l3machus/BabelStrike" nocase ascii wide

    condition:
        any of them
}