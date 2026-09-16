rule rule_Snaffler_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Snaffler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Snaffler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Snaffler_offensive_tool_keyword = /\ssnaffler\.log/ nocase ascii wide
                        $string2_Snaffler_offensive_tool_keyword = /\/ShareFinder\.cs/ nocase ascii wide
                        $string3_Snaffler_offensive_tool_keyword = /\/SnaffCon\.cs/ nocase ascii wide
                        $string4_Snaffler_offensive_tool_keyword = "/SnaffCon/Snaffler" nocase ascii wide
                        $string5_Snaffler_offensive_tool_keyword = "/SnaffCore/" nocase ascii wide
                        $string6_Snaffler_offensive_tool_keyword = "/snafflertest/" nocase ascii wide
                        $string7_Snaffler_offensive_tool_keyword = /\/TreeWalker\.cs/ nocase ascii wide
                        $string8_Snaffler_offensive_tool_keyword = "SnaffCon/Snaffler" nocase ascii wide
                        $string9_Snaffler_offensive_tool_keyword = /SnaffCore\.csproj/ nocase ascii wide
                        $string10_Snaffler_offensive_tool_keyword = "SnaffCore/ActiveDirectory" nocase ascii wide
                        $string11_Snaffler_offensive_tool_keyword = "SnaffCore/Classifiers" nocase ascii wide
                        $string12_Snaffler_offensive_tool_keyword = "SnaffCore/Concurrency" nocase ascii wide
                        $string13_Snaffler_offensive_tool_keyword = "SnaffCore/Config" nocase ascii wide
                        $string14_Snaffler_offensive_tool_keyword = "SnaffCore/ShareFind" nocase ascii wide
                        $string15_Snaffler_offensive_tool_keyword = "SnaffCore/TreeWalk" nocase ascii wide
                        $string16_Snaffler_offensive_tool_keyword = /Snaffler\.csproj/ nocase ascii wide
                        $string17_Snaffler_offensive_tool_keyword = /snaffler\.exe/ nocase ascii wide
                        $string18_Snaffler_offensive_tool_keyword = /snaffler\.exe/ nocase ascii wide
                        $string19_Snaffler_offensive_tool_keyword = /snaffler\.log/ nocase ascii wide
                        $string20_Snaffler_offensive_tool_keyword = /Snaffler\.sln/ nocase ascii wide
                        $string21_Snaffler_offensive_tool_keyword = /Snaffler\.sln/ nocase ascii wide
                        $string22_Snaffler_offensive_tool_keyword = /SnafflerMessage\.cs/ nocase ascii wide
                        $string23_Snaffler_offensive_tool_keyword = /SnafflerMessageType\.cs/ nocase ascii wide
                        $string24_Snaffler_offensive_tool_keyword = /UltraSnaffCore\.csproj/ nocase ascii wide
                        $string25_Snaffler_offensive_tool_keyword = /UltraSnaffler\.sln/ nocase ascii wide
                        $string26_Snaffler_offensive_tool_keyword = /UltraSnaffler\.sln/ nocase ascii wide

    condition:
        any of them
}