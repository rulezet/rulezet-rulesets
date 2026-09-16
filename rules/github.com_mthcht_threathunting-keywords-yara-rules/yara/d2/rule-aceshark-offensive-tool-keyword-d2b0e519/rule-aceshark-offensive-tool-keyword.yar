rule rule_ACEshark_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ACEshark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ACEshark"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ACEshark_offensive_tool_keyword = /\sACEshark\.py/ nocase ascii wide
                        $string2_ACEshark_offensive_tool_keyword = /\.ACEshark\.log/ nocase ascii wide
                        $string3_ACEshark_offensive_tool_keyword = /\/\.ACEshark/ nocase ascii wide
                        $string4_ACEshark_offensive_tool_keyword = /\/ACEshark\.git/ nocase ascii wide
                        $string5_ACEshark_offensive_tool_keyword = /\/ACEshark\.py/ nocase ascii wide
                        $string6_ACEshark_offensive_tool_keyword = /\\ACEshark\.log/ nocase ascii wide
                        $string7_ACEshark_offensive_tool_keyword = /\\ACEshark\.py/ nocase ascii wide
                        $string8_ACEshark_offensive_tool_keyword = "0e9af89e0f2faa8d7f92d6e9538e19f82c701c798031d890978845e388b85ba6" nocase ascii wide
                        $string9_ACEshark_offensive_tool_keyword = "7fa5122ff9fabaf2676064087eacaf4a63b386bb27d50ac345ff4bdbe6a4f7d5" nocase ascii wide
                        $string10_ACEshark_offensive_tool_keyword = "e07330a2c8c8678fce26c761437a3ed5cf38881baea403a376a5b3b9b5ef9d27" nocase ascii wide
                        $string11_ACEshark_offensive_tool_keyword = "t3l3machus/ACEshark" nocase ascii wide

    condition:
        any of them
}