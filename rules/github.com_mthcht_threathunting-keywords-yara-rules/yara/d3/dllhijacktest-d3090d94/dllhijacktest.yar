rule DLLHijackTest
{
    meta:
        description = "Detection patterns for the tool 'DLLHijackTest' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLLHijackTest"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DLLHijackTest\.git/ nocase ascii wide
                        $string2 = /\[\+\]\sParsed\sProcmon\soutput\sfor\spotential\sDLL\shijack\spaths\!/ nocase ascii wide
                        $string3 = "644758B1-C146-4D3B-B614-8EB6C933B0AA" nocase ascii wide
                        $string4 = /DLLHijackTest\.dll/ nocase ascii wide
                        $string5 = /DLLHijackTest\.sln/ nocase ascii wide
                        $string6 = "DLLHijackTest-master" nocase ascii wide
                        $string7 = "Get-PotentialDLLHijack" nocase ascii wide
                        $string8 = "slyd0g/DLLHijackTest" nocase ascii wide

    condition:
        any of them
}