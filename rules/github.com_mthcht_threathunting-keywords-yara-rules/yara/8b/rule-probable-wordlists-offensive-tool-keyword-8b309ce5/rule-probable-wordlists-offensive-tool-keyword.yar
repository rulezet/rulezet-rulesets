rule rule_Probable_Wordlists_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Probable-Wordlists' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Probable-Wordlists"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Probable_Wordlists_offensive_tool_keyword = "Probable-Wordlists" nocase ascii wide
                        $string2_Probable_Wordlists_offensive_tool_keyword = "Probable-Wordlists" nocase ascii wide
                        $string3_Probable_Wordlists_offensive_tool_keyword = "Real-Passwords" nocase ascii wide
                        $string4_Probable_Wordlists_offensive_tool_keyword = /Top109Million\-probable\-v2\.txt/ nocase ascii wide
                        $string5_Probable_Wordlists_offensive_tool_keyword = /Top12Thousand\-probable\-v2\.txt/ nocase ascii wide
                        $string6_Probable_Wordlists_offensive_tool_keyword = /Top1575\-probable\-v2\.txt/ nocase ascii wide
                        $string7_Probable_Wordlists_offensive_tool_keyword = /Top1pt6Million\-probable\-v2\.txt/ nocase ascii wide
                        $string8_Probable_Wordlists_offensive_tool_keyword = /Top207\-probable\-v2\.txt/ nocase ascii wide
                        $string9_Probable_Wordlists_offensive_tool_keyword = /Top29Million\-probable\-v2\.txt/ nocase ascii wide
                        $string10_Probable_Wordlists_offensive_tool_keyword = /Top2Billion\-probable\-v2\.txt/ nocase ascii wide
                        $string11_Probable_Wordlists_offensive_tool_keyword = /Top304Thousand\-probable\-v2\.txt/ nocase ascii wide
                        $string12_Probable_Wordlists_offensive_tool_keyword = /Top353Million\-probable\-v2\.txt/ nocase ascii wide

    condition:
        any of them
}