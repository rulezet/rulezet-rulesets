rule NoFilter
{
    meta:
        description = "Detection patterns for the tool 'NoFilter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoFilter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/NoFilter\.cpp/ nocase ascii wide
                        $string2 = /\/NoFilter\.exe/ nocase ascii wide
                        $string3 = /\/NoFilter\.git/ nocase ascii wide
                        $string4 = /\/NoFilter\.sln/ nocase ascii wide
                        $string5 = /\/NoFilter\.vcxproj/ nocase ascii wide
                        $string6 = /\\NoFilter\.cpp/ nocase ascii wide
                        $string7 = /\\NoFilter\.exe/ nocase ascii wide
                        $string8 = /\\NoFilter\.sln/ nocase ascii wide
                        $string9 = /\\NoFilter\.vcxproj/ nocase ascii wide
                        $string10 = "2CFB9E9E-479D-4E23-9A8E-18C92E06B731" nocase ascii wide
                        $string11 = "deepinstinct/NoFilter" nocase ascii wide
                        $string12 = /NoFilter\.exe\s/ nocase ascii wide
                        $string13 = /NoFilter\-main\.zip/ nocase ascii wide
                        $string14 = /WfpEscalation\.exe/ nocase ascii wide

    condition:
        any of them
}