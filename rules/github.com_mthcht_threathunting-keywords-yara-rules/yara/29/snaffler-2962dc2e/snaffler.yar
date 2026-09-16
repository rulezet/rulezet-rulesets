rule Snaffler
{
    meta:
        description = "Detection patterns for the tool 'Snaffler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Snaffler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\ssnaffler\.log/ nocase ascii wide
                        $string2 = /\/ShareFinder\.cs/ nocase ascii wide
                        $string3 = /\/SnaffCon\.cs/ nocase ascii wide
                        $string4 = "/SnaffCon/Snaffler" nocase ascii wide
                        $string5 = "/SnaffCore/" nocase ascii wide
                        $string6 = "/snafflertest/" nocase ascii wide
                        $string7 = /\/TreeWalker\.cs/ nocase ascii wide
                        $string8 = "SnaffCon/Snaffler" nocase ascii wide
                        $string9 = /SnaffCore\.csproj/ nocase ascii wide
                        $string10 = "SnaffCore/ActiveDirectory" nocase ascii wide
                        $string11 = "SnaffCore/Classifiers" nocase ascii wide
                        $string12 = "SnaffCore/Concurrency" nocase ascii wide
                        $string13 = "SnaffCore/Config" nocase ascii wide
                        $string14 = "SnaffCore/ShareFind" nocase ascii wide
                        $string15 = "SnaffCore/TreeWalk" nocase ascii wide
                        $string16 = /Snaffler\.csproj/ nocase ascii wide
                        $string17 = /snaffler\.exe/ nocase ascii wide
                        $string18 = /snaffler\.exe/ nocase ascii wide
                        $string19 = /snaffler\.log/ nocase ascii wide
                        $string20 = /Snaffler\.sln/ nocase ascii wide
                        $string21 = /Snaffler\.sln/ nocase ascii wide
                        $string22 = /SnafflerMessage\.cs/ nocase ascii wide
                        $string23 = /SnafflerMessageType\.cs/ nocase ascii wide
                        $string24 = /UltraSnaffCore\.csproj/ nocase ascii wide
                        $string25 = /UltraSnaffler\.sln/ nocase ascii wide
                        $string26 = /UltraSnaffler\.sln/ nocase ascii wide

    condition:
        any of them
}