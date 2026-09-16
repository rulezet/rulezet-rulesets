rule rule_COMHunter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'COMHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "COMHunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_COMHunter_offensive_tool_keyword = /COMHunter.{0,1000}\s\-inproc/ nocase ascii wide
                        $string2_COMHunter_offensive_tool_keyword = /COMHunter.{0,1000}\s\-localserver/ nocase ascii wide
                        $string3_COMHunter_offensive_tool_keyword = /COMHunter\.csproj/ nocase ascii wide
                        $string4_COMHunter_offensive_tool_keyword = /COMHunter\.exe/ nocase ascii wide
                        $string5_COMHunter_offensive_tool_keyword = /COMHunter\.sln/ nocase ascii wide
                        $string6_COMHunter_offensive_tool_keyword = /github.{0,1000}\/COMHunter\// nocase ascii wide

    condition:
        any of them
}