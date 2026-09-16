rule rule_NoFilter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NoFilter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoFilter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NoFilter_offensive_tool_keyword = /\/NoFilter\.cpp/ nocase ascii wide
                        $string2_NoFilter_offensive_tool_keyword = /\/NoFilter\.exe/ nocase ascii wide
                        $string3_NoFilter_offensive_tool_keyword = /\/NoFilter\.git/ nocase ascii wide
                        $string4_NoFilter_offensive_tool_keyword = /\/NoFilter\.sln/ nocase ascii wide
                        $string5_NoFilter_offensive_tool_keyword = /\/NoFilter\.vcxproj/ nocase ascii wide
                        $string6_NoFilter_offensive_tool_keyword = /\\NoFilter\.cpp/ nocase ascii wide
                        $string7_NoFilter_offensive_tool_keyword = /\\NoFilter\.exe/ nocase ascii wide
                        $string8_NoFilter_offensive_tool_keyword = /\\NoFilter\.sln/ nocase ascii wide
                        $string9_NoFilter_offensive_tool_keyword = /\\NoFilter\.vcxproj/ nocase ascii wide
                        $string10_NoFilter_offensive_tool_keyword = "2CFB9E9E-479D-4E23-9A8E-18C92E06B731" nocase ascii wide
                        $string11_NoFilter_offensive_tool_keyword = "deepinstinct/NoFilter" nocase ascii wide
                        $string12_NoFilter_offensive_tool_keyword = /NoFilter\.exe\s/ nocase ascii wide
                        $string13_NoFilter_offensive_tool_keyword = /NoFilter\-main\.zip/ nocase ascii wide
                        $string14_NoFilter_offensive_tool_keyword = /WfpEscalation\.exe/ nocase ascii wide

    condition:
        any of them
}