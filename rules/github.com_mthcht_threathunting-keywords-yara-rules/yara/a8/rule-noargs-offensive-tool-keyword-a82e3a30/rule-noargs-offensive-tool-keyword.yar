rule rule_NoArgs_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NoArgs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoArgs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NoArgs_offensive_tool_keyword = /\/NoArgs\.exe/ nocase ascii wide
                        $string2_NoArgs_offensive_tool_keyword = /\/NoArgs\.git/ nocase ascii wide
                        $string3_NoArgs_offensive_tool_keyword = /\[i\]\sArgument\sSpoofed\./ nocase ascii wide
                        $string4_NoArgs_offensive_tool_keyword = /\\NoArgs\.cpp/ nocase ascii wide
                        $string5_NoArgs_offensive_tool_keyword = /\\NoArgs\.exe/ nocase ascii wide
                        $string6_NoArgs_offensive_tool_keyword = /\\NoArgs\.exe\.config/ nocase ascii wide
                        $string7_NoArgs_offensive_tool_keyword = /\\NoArgs\.exe\.log/ nocase ascii wide
                        $string8_NoArgs_offensive_tool_keyword = /\\NoArgs_Encrypted\.exe/ nocase ascii wide
                        $string9_NoArgs_offensive_tool_keyword = "6a14782fd71e08ded40b8652783cb49695b09e4abbaaf8c22cc22d582032191f" nocase ascii wide
                        $string10_NoArgs_offensive_tool_keyword = "8c7d64cec00aafa23884f1bb28337ef6ce49f2f90605800217f635526e38541d" nocase ascii wide
                        $string11_NoArgs_offensive_tool_keyword = "oh-az/NoArgs" nocase ascii wide

    condition:
        any of them
}