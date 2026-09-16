rule rule_AutoSmuggle_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AutoSmuggle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoSmuggle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AutoSmuggle_offensive_tool_keyword = /\/AutoSmuggle\.git/ nocase ascii wide
                        $string2_AutoSmuggle_offensive_tool_keyword = /\[.{0,1000}\]\sSmuggling\sin\sHTML/ nocase ascii wide
                        $string3_AutoSmuggle_offensive_tool_keyword = /\[.{0,1000}\]\sSmuggling\sin\sSVG/ nocase ascii wide
                        $string4_AutoSmuggle_offensive_tool_keyword = /\\AutoSmuggle\\.{0,1000}\.cs/ nocase ascii wide
                        $string5_AutoSmuggle_offensive_tool_keyword = "57A893C7-7527-4B55-B4E9-D644BBDA89D1" nocase ascii wide
                        $string6_AutoSmuggle_offensive_tool_keyword = /AutoSmuggle\.csproj/ nocase ascii wide
                        $string7_AutoSmuggle_offensive_tool_keyword = /AutoSmuggle\.exe/ nocase ascii wide
                        $string8_AutoSmuggle_offensive_tool_keyword = /AutoSmuggle\.sln/ nocase ascii wide
                        $string9_AutoSmuggle_offensive_tool_keyword = "AutoSmuggle-master" nocase ascii wide
                        $string10_AutoSmuggle_offensive_tool_keyword = "surajpkhetani/AutoSmuggle" nocase ascii wide

    condition:
        any of them
}