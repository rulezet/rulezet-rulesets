rule AutoSmuggle
{
    meta:
        description = "Detection patterns for the tool 'AutoSmuggle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoSmuggle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/AutoSmuggle\.git/ nocase ascii wide
                        $string2 = /\[.{0,1000}\]\sSmuggling\sin\sHTML/ nocase ascii wide
                        $string3 = /\[.{0,1000}\]\sSmuggling\sin\sSVG/ nocase ascii wide
                        $string4 = /\\AutoSmuggle\\.{0,1000}\.cs/ nocase ascii wide
                        $string5 = "57A893C7-7527-4B55-B4E9-D644BBDA89D1" nocase ascii wide
                        $string6 = /AutoSmuggle\.csproj/ nocase ascii wide
                        $string7 = /AutoSmuggle\.exe/ nocase ascii wide
                        $string8 = /AutoSmuggle\.sln/ nocase ascii wide
                        $string9 = "AutoSmuggle-master" nocase ascii wide
                        $string10 = "surajpkhetani/AutoSmuggle" nocase ascii wide

    condition:
        any of them
}