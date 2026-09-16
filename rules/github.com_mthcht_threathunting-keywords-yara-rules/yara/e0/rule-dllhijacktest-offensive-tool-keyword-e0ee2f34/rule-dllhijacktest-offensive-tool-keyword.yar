rule rule_DLLHijackTest_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DLLHijackTest' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLLHijackTest"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DLLHijackTest_offensive_tool_keyword = /\/DLLHijackTest\.git/ nocase ascii wide
                        $string2_DLLHijackTest_offensive_tool_keyword = /\[\+\]\sParsed\sProcmon\soutput\sfor\spotential\sDLL\shijack\spaths\!/ nocase ascii wide
                        $string3_DLLHijackTest_offensive_tool_keyword = "644758B1-C146-4D3B-B614-8EB6C933B0AA" nocase ascii wide
                        $string4_DLLHijackTest_offensive_tool_keyword = /DLLHijackTest\.dll/ nocase ascii wide
                        $string5_DLLHijackTest_offensive_tool_keyword = /DLLHijackTest\.sln/ nocase ascii wide
                        $string6_DLLHijackTest_offensive_tool_keyword = "DLLHijackTest-master" nocase ascii wide
                        $string7_DLLHijackTest_offensive_tool_keyword = "Get-PotentialDLLHijack" nocase ascii wide
                        $string8_DLLHijackTest_offensive_tool_keyword = "slyd0g/DLLHijackTest" nocase ascii wide

    condition:
        any of them
}